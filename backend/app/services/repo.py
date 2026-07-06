import json
import logging
import asyncio
import httpx
import re
import base64
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.scan import RepoScan, RepoFileResult, ScanStatus, SeverityLevel
from app.schemas.scan import RepoAuditStatusResponse
from app.services.gemini import gemini_service
from app.services.analyzer import run_regex_scan
from app.database import async_session

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"

SCANNABLE_EXTENSIONS = {
    ".py": "python", ".js": "javascript", ".ts": "typescript",
    ".jsx": "javascript", ".tsx": "typescript", ".java": "java",
    ".kt": "kotlin", ".go": "go", ".rb": "ruby", ".php": "php",
    ".cs": "csharp", ".cpp": "cpp", ".c": "c", ".rs": "rust",
    ".swift": "swift", ".sh": "bash", ".sql": "sql",
}

SKIP_DIRS = {
    "node_modules", ".git", "vendor", "dist", "build",
    "__pycache__", ".venv", "venv", "env", ".env",
    "target", "bin", "obj", ".idea", ".vscode",
}

MAX_FILES = 20
MAX_FILE_SIZE = 50_000


def parse_github_url(url: str) -> tuple[str, str]:
    url = url.strip().rstrip("/")
    url = re.sub(r"^https?://", "", url)
    url = re.sub(r"^www\.", "", url)
    parts = url.split("/")
    if len(parts) < 3 or parts[0].lower() != "github.com":
        raise ValueError(f"Not a valid GitHub URL: {url}")
    owner = parts[1]
    repo = parts[2].removesuffix(".git")
    if not owner or not repo:
        raise ValueError("Could not extract owner/repo from URL")
    return owner, repo


async def _github_get(client: httpx.AsyncClient, path: str) -> dict | list:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    try:
        from app.config import settings
        token = getattr(settings, "GITHUB_TOKEN", None)
        if token:
            headers["Authorization"] = f"Bearer {token}"
    except Exception:
        pass
    resp = await client.get(f"{GITHUB_API}{path}", headers=headers, timeout=20)
    resp.raise_for_status()
    return resp.json()


async def fetch_repo_files(owner: str, repo: str) -> list[dict]:
    files = []
    async with httpx.AsyncClient() as client:
        repo_info = await _github_get(client, f"/repos/{owner}/{repo}")
        default_branch = repo_info.get("default_branch", "main")

        tree_data = await _github_get(
            client,
            f"/repos/{owner}/{repo}/git/trees/{default_branch}?recursive=1"
        )
        tree = tree_data.get("tree", [])

        candidates = []
        for item in tree:
            if item.get("type") != "blob":
                continue
            path = item.get("path", "")
            path_parts = path.split("/")
            if any(part in SKIP_DIRS for part in path_parts[:-1]):
                continue
            ext = "." + path.rsplit(".", 1)[-1] if "." in path else ""
            language = SCANNABLE_EXTENSIONS.get(ext.lower())
            if not language:
                continue
            size = item.get("size", 0)
            if size > MAX_FILE_SIZE:
                continue
            candidates.append({"path": path, "language": language, "sha": item.get("sha")})

        candidates = candidates[:MAX_FILES]

        async def fetch_content(item: dict) -> Optional[dict]:
            try:
                blob = await _github_get(client, f"/repos/{owner}/{repo}/git/blobs/{item['sha']}")
                content_b64 = blob.get("content", "").replace("\n", "")
                content = base64.b64decode(content_b64).decode("utf-8", errors="replace")
                return {"path": item["path"], "language": item["language"], "content": content}
            except Exception as e:
                logger.warning(f"Failed to fetch {item['path']}: {e}")
                return None

        batch_size = 5
        for i in range(0, len(candidates), batch_size):
            batch = candidates[i:i + batch_size]
            results = await asyncio.gather(*[fetch_content(c) for c in batch])
            files.extend([r for r in results if r is not None])
            if i + batch_size < len(candidates):
                await asyncio.sleep(0.5)

    return files


def _normalize_sev(raw: str) -> str:
    s = (raw or "medium").lower().strip()
    return s if s in {"critical", "high", "medium", "low", "info"} else "medium"


def _count_severity(issues: list[dict], level: str) -> int:
    return sum(1 for i in issues if _normalize_sev(i.get("severity", "")) == level)


def _compute_score(critical: int, high: int, medium: int) -> str:
    if critical > 0: return "F"
    if high > 3: return "D"
    if high > 0: return "C"
    if medium > 5: return "C"
    if medium > 0: return "B"
    return "A"


async def perform_repo_audit(repo_scan_id: int):
    async with async_session() as db:
        try:
            result = await db.execute(select(RepoScan).where(RepoScan.id == repo_scan_id))
            repo_scan = result.scalar_one_or_none()
            if not repo_scan:
                return

            repo_scan.status = ScanStatus.SCANNING
            await db.commit()

            try:
                owner, repo_name = parse_github_url(repo_scan.repo_url)
            except ValueError as e:
                logger.error(f"Invalid GitHub URL: {e}")
                repo_scan.status = ScanStatus.FAILED
                await db.commit()
                return

            try:
                files = await fetch_repo_files(owner, repo_name)
            except httpx.HTTPStatusError as e:
                status_code = e.response.status_code
                if status_code == 404:
                    logger.error(f"Repo not found: {owner}/{repo_name}")
                elif status_code == 403:
                    logger.error("GitHub rate limit — add GITHUB_TOKEN to .env")
                else:
                    logger.error(f"GitHub API error {status_code}")
                repo_scan.status = ScanStatus.FAILED
                await db.commit()
                return
            except Exception as e:
                logger.error(f"Failed to fetch repo files: {e}", exc_info=True)
                repo_scan.status = ScanStatus.FAILED
                await db.commit()
                return

            if not files:
                repo_scan.status = ScanStatus.COMPLETED
                repo_scan.total_files = 0
                repo_scan.total_vulnerabilities = 0
                repo_scan.security_score = "A"
                await db.commit()
                return

            total_critical = total_high = total_medium = total_low = total_vulns = 0

            for file_info in files:
                code = file_info["content"]
                language = file_info["language"]
                file_path = file_info["path"]
                issues = []

                try:
                    regex_results = run_regex_scan(code, language)
                    for detected in regex_results:
                        issues.append({
                            "title": detected.rule.name,
                            "severity": _normalize_sev(detected.rule.severity),
                            "line_number": detected.line_number,
                            "description": detected.rule.description,
                            "fix_suggestion": f"Rule {detected.rule.id}: {detected.rule.description}",
                            "issue_type": "SECURITY",
                            "category": getattr(detected.rule, "category", "Security"),
                        })
                except Exception as e:
                    logger.warning(f"Regex scan failed for {file_path}: {e}")

                try:
                    ai_result = await gemini_service.analyze_repo_file(code, language, file_path)
                    ai_vulns = ai_result.get("vulnerabilities", [])
                    existing_titles = {i["title"].lower() for i in issues}

                    for v in ai_vulns:
                        title = v.get("title", "").strip()
                        if not title or title.lower() in existing_titles:
                            continue
                        issue_type = v.get("issue_type", "SECURITY").upper()
                        raw_cat = v.get("category") or ""
                        category = f"Bug-{raw_cat}" if issue_type == "BUG" and not raw_cat.startswith("Bug-") else raw_cat
                        issues.append({
                            "title": title,
                            "severity": _normalize_sev(v.get("severity", "medium")),
                            "line_number": v.get("line_number"),
                            "description": v.get("description", ""),
                            "fix_suggestion": v.get("fix_suggestion"),
                            "issue_type": issue_type,
                            "category": category,
                        })
                        existing_titles.add(title.lower())
                except Exception as e:
                    logger.warning(f"AI scan failed for {file_path}: {e}")

                fc = _count_severity(issues, "critical")
                fh = _count_severity(issues, "high")
                fm = _count_severity(issues, "medium")
                fl = _count_severity(issues, "low") + _count_severity(issues, "info")

                total_critical += fc
                total_high += fh
                total_medium += fm
                total_low += fl
                total_vulns += len(issues)

                db.add(RepoFileResult(
                    repo_scan_id=repo_scan_id,
                    file_path=file_path,
                    language=language,
                    vulnerability_count=len(issues),
                    issues=json.dumps(issues),
                ))

            repo_scan.status = ScanStatus.COMPLETED
            repo_scan.security_score = _compute_score(total_critical, total_high, total_medium)
            repo_scan.total_files = len(files)
            repo_scan.total_vulnerabilities = total_vulns
            repo_scan.critical_count = total_critical
            repo_scan.high_count = total_high
            repo_scan.medium_count = total_medium
            repo_scan.low_count = total_low
            await db.commit()
            logger.info(f"Repo audit {repo_scan_id} done: {len(files)} files, {total_vulns} issues, score={repo_scan.security_score}")

        except Exception as e:
            logger.error(f"Repo audit {repo_scan_id} failed: {e}", exc_info=True)
            try:
                result = await db.execute(select(RepoScan).where(RepoScan.id == repo_scan_id))
                repo_scan = result.scalar_one_or_none()
                if repo_scan:
                    repo_scan.status = ScanStatus.FAILED
                    await db.commit()
            except Exception:
                pass


async def create_repo_audit(repo_url: str, db: AsyncSession) -> RepoScan:
    repo_scan = RepoScan(repo_url=repo_url, status=ScanStatus.PENDING)
    db.add(repo_scan)
    await db.commit()
    await db.refresh(repo_scan)
    asyncio.create_task(perform_repo_audit(repo_scan.id))
    return repo_scan


async def get_repo_audit(repo_scan_id: int, db: AsyncSession) -> Optional[RepoScan]:
    result = await db.execute(select(RepoScan).where(RepoScan.id == repo_scan_id))
    return result.scalar_one_or_none()


async def get_repo_audit_status(repo_scan_id: int, db: AsyncSession) -> Optional[RepoAuditStatusResponse]:
    result = await db.execute(select(RepoScan).where(RepoScan.id == repo_scan_id))
    repo_scan = result.scalar_one_or_none()
    if not repo_scan:
        return None
    progress = {
        ScanStatus.PENDING: 5,
        ScanStatus.SCANNING: 50,
        ScanStatus.COMPLETED: 100,
        ScanStatus.FAILED: 0,
    }.get(repo_scan.status, 0)
    return RepoAuditStatusResponse(
        id=repo_scan.id,
        repo_url=repo_scan.repo_url,
        status=repo_scan.status,
        security_score=repo_scan.security_score,
        progress=progress,
    )