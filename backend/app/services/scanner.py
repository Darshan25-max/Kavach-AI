import logging
import asyncio
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from sqlalchemy.orm import selectinload

from app.models.scan import Scan, Vulnerability, ScanStatus, SeverityLevel, RepoScan, RepoFileResult
from app.schemas.scan import (
    ScanRequest, ScanResponse, ScanListItem, ScanListResponse,
    LiveReviewRequest, LiveReviewResponse, LiveReviewIssue,
)
from app.services.analyzer import run_regex_scan, run_bug_scan, compute_code_hash, detect_language_safe
from app.services.gemini import gemini_service
from app.database import async_session

logger = logging.getLogger(__name__)

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}

BUG_TITLE_KEYWORDS = (
    "division by zero", "zerodivision", "off-by-one", "off by one",
    "file handle", "resource leak", "null dereference", "none dereference",
    "infinite loop", "missing return", "unhandled exception", "index out",
    "mutable default", "wrong operator", "dead code", "unreachable",
    "type mismatch", "missing base case", "missing edge", "memory leak",
    "unclosed", "handle leak", "attribute error", "name error",
    "empty list", "divide", "division",
)


def _normalize_severity(raw: str) -> str:
    s = (raw or "medium").lower().strip()
    return s if s in VALID_SEVERITIES else "medium"


def _resolve_issue_type(ai_vuln: dict) -> str:
    """Determine issue_type from Gemini output with multiple fallbacks."""
    # 1. Explicit field
    explicit = (ai_vuln.get("issue_type") or "").upper().strip()
    if explicit in ("BUG", "SECURITY"):
        return explicit

    # 2. Category prefix
    category = (ai_vuln.get("category") or "").lower()
    if category.startswith("bug-"):
        return "BUG"

    # 3. Title/description keywords
    title = (ai_vuln.get("title") or "").lower()
    desc  = (ai_vuln.get("description") or "").lower()
    if any(kw in title or kw in desc for kw in BUG_TITLE_KEYWORDS):
        return "BUG"

    return "SECURITY"


def _build_category(ai_vuln: dict, issue_type: str) -> str:
    raw = (ai_vuln.get("category") or "").strip()
    if issue_type == "BUG" and raw and not raw.lower().startswith("bug-"):
        return f"Bug-{raw}"
    if issue_type == "BUG" and not raw:
        return "Bug-General"
    return raw


async def perform_scan(scan_id: int):
    """Background task: full code scan (regex + bug rules + AI)."""
    async with async_session() as db:
        try:
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            if not scan:
                return

            scan.status = ScanStatus.SCANNING
            await db.commit()

            code = scan.code
            language = scan.language
            vulnerabilities = []
            all_titles = set()

            # ── Step 1: Regex security rules ──────────────────────────────
            regex_results = run_regex_scan(code, language)
            for detected in regex_results:
                vuln = Vulnerability(
                    scan_id=scan_id,
                    severity=_normalize_severity(detected.rule.severity),
                    title=detected.rule.name,
                    description=detected.rule.description,
                    line_number=detected.line_number,
                    code_snippet=detected.code_snippet,
                    fix_suggestion=f"Rule {detected.rule.id}: {detected.rule.description}",
                    cwe_id=getattr(detected.rule, "cwe_id", None),
                    category=getattr(detected.rule, "category", "Security"),
                )
                vulnerabilities.append(vuln)
                all_titles.add(detected.rule.name.lower())

            # ── Step 2: Hardcoded bug rules ───────────────────────────────
            bug_results = run_bug_scan(code, language)
            for bug in bug_results:
                title = bug["title"]
                # Deduplicate by title+line
                key = f"{title.lower()}:{bug.get('line_number', 0)}"
                if key in all_titles:
                    continue
                all_titles.add(key)

                vuln = Vulnerability(
                    scan_id=scan_id,
                    severity=_normalize_severity(bug["severity"]),
                    title=title,
                    description=bug["description"],
                    line_number=bug.get("line_number"),
                    code_snippet=bug.get("code_snippet"),
                    fix_suggestion=bug.get("fix_suggestion"),
                    cwe_id=bug.get("cwe_id"),
                    category=bug["category"],  # already "Bug-XXX"
                )
                vulnerabilities.append(vuln)

            # ── Step 3: Gemini AI (security + additional bugs) ────────────
            ai_result = await gemini_service.analyze_vulnerabilities(code, language)
            ai_vulns = ai_result.get("vulnerabilities", [])

            logger.info(f"Scan {scan_id}: Gemini returned {len(ai_vulns)} issues, "
                       f"regex={len(regex_results)}, bugs={len(bug_results)}")

            for ai_vuln in ai_vulns:
                title = (ai_vuln.get("title") or "").strip()
                if not title:
                    continue

                # Skip if already caught by regex or bug rules
                if title.lower() in all_titles:
                    continue
                # Also skip if similar title already exists (avoid near-duplicates)
                if any(title.lower() in t or t in title.lower() for t in all_titles):
                    continue

                issue_type = _resolve_issue_type(ai_vuln)
                category   = _build_category(ai_vuln, issue_type)

                vuln = Vulnerability(
                    scan_id=scan_id,
                    severity=_normalize_severity(ai_vuln.get("severity", "medium")),
                    title=title[:255],
                    description=ai_vuln.get("description", ""),
                    line_number=ai_vuln.get("line_number"),
                    code_snippet=ai_vuln.get("code_snippet"),
                    fix_suggestion=ai_vuln.get("fix_suggestion"),
                    cwe_id=ai_vuln.get("cwe_id"),
                    category=category,
                )
                vulnerabilities.append(vuln)
                all_titles.add(title.lower())

            # ── Step 4: Save and update counts ────────────────────────────
            db.add_all(vulnerabilities)

            scan.total_vulnerabilities = len(vulnerabilities)
            scan.critical_count = sum(1 for v in vulnerabilities if v.severity == SeverityLevel.CRITICAL)
            scan.high_count     = sum(1 for v in vulnerabilities if v.severity == SeverityLevel.HIGH)
            scan.medium_count   = sum(1 for v in vulnerabilities if v.severity == SeverityLevel.MEDIUM)
            scan.low_count      = sum(1 for v in vulnerabilities if v.severity in (SeverityLevel.LOW, SeverityLevel.INFO))
            scan.status = ScanStatus.COMPLETED

            await db.commit()

            bug_count = sum(1 for v in vulnerabilities if (v.category or "").lower().startswith("bug-"))
            sec_count = len(vulnerabilities) - bug_count
            logger.info(f"Scan {scan_id} complete: {sec_count} security, {bug_count} bugs")

        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}", exc_info=True)
            try:
                result = await db.execute(select(Scan).where(Scan.id == scan_id))
                scan = result.scalar_one_or_none()
                if scan:
                    scan.status = ScanStatus.FAILED
                    await db.commit()
            except Exception:
                pass


async def create_scan(request: ScanRequest, db: AsyncSession) -> Scan:
    language = detect_language_safe(request.code, request.language)
    code_hash = compute_code_hash(request.code)
    scan = Scan(
        code_hash=code_hash,
        language=language,
        code=request.code,
        status=ScanStatus.PENDING,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    asyncio.create_task(perform_scan(scan.id))
    return scan


async def get_scan(scan_id: int, db: AsyncSession) -> Optional[Scan]:
    result = await db.execute(
        select(Scan)
        .options(selectinload(Scan.vulnerabilities))
        .where(Scan.id == scan_id)
    )
    return result.scalar_one_or_none()


async def list_scans(db: AsyncSession, page: int = 1, page_size: int = 20) -> ScanListResponse:
    count_result = await db.execute(select(func.count(Scan.id)))
    total = count_result.scalar() or 0
    offset = (page - 1) * page_size
    result = await db.execute(
        select(Scan).order_by(desc(Scan.created_at)).offset(offset).limit(page_size)
    )
    scans = result.scalars().all()
    return ScanListResponse(
        scans=[ScanListItem.model_validate(s) for s in scans],
        total=total,
        page=page,
        page_size=page_size,
    )


async def perform_live_review(request: LiveReviewRequest, db: AsyncSession) -> LiveReviewResponse:
    language = detect_language_safe(request.code, request.language)
    regex_results = run_regex_scan(request.code, language)
    ai_issues = await gemini_service.live_review(request.code, language)
    issues = []

    for detected in regex_results[:5]:
        issues.append(LiveReviewIssue(
            line=detected.line_number,
            severity=_normalize_severity(detected.rule.severity),
            message=f"[SECURITY] {detected.rule.name}",
            suggestion=detected.rule.description[:200],
        ))

    for ai_issue in ai_issues[:10]:
        issues.append(LiveReviewIssue(
            line=ai_issue.get("line", 1),
            severity=_normalize_severity(ai_issue.get("severity", "medium")),
            message=ai_issue.get("message", ""),
            suggestion=ai_issue.get("suggestion"),
        ))

    critical = sum(1 for i in issues if i.severity == "critical")
    high     = sum(1 for i in issues if i.severity == "high")
    medium   = sum(1 for i in issues if i.severity == "medium")

    if critical > 0:   score = "F"
    elif high > 2:     score = "D"
    elif high > 0:     score = "C"
    elif medium > 3:   score = "C"
    elif medium > 0:   score = "B"
    else:              score = "A"

    return LiveReviewResponse(issues=issues, language=language, overall_score=score)