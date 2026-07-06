import json
import logging
from typing import Optional
from google import genai
from google.genai import types
from app.config import settings

logger = logging.getLogger(__name__)


VULNERABILITY_ANALYSIS_PROMPT = """You are KavachAI, an expert code analyst. Analyze the following {language} code.

You MUST find TWO separate types of issues and label each one correctly:

TYPE 1 — SECURITY (issue_type must be "SECURITY"):
SQL injection, command injection, XSS, hardcoded passwords/secrets/keys, path traversal,
insecure crypto (MD5/SHA1), SSRF, XXE, CSRF, broken auth, sensitive data exposure.

TYPE 2 — BUG (issue_type must be "BUG"):
- Division by zero (a / b with no b==0 check)
- File handle leak (open() without context manager / without .close())
- Off-by-one (range(len(x)-1) misses last element)
- ZeroDivisionError (sum / len with no empty check)
- Mutable default argument (def f(x=[]))
- Null/None dereference
- Infinite loop / missing break
- Wrong operator (= vs ==, & vs &&)
- Unhandled exception
- Resource leak
- Missing return value
- Unreachable / dead code

Code:
```
{code}
```

Return ONLY this JSON (no markdown, no text outside JSON):
{{
    "vulnerabilities": [
        {{
            "title": "Short title",
            "description": "Simple plain-English explanation of the problem",
            "severity": "critical|high|medium|low",
            "line_number": <integer or null>,
            "code_snippet": "the bad line(s) of code",
            "fix_suggestion": "Exact corrected code showing how to fix it",
            "cwe_id": "CWE-XXX or null",
            "issue_type": "SECURITY or BUG — REQUIRED, never omit this field",
            "category": "for SECURITY use: Injection/XSS/Authentication/Cryptography/Configuration — for BUG use: Bug-ZeroDivision/Bug-ResourceLeak/Bug-OffByOne/Bug-NullDereference/Bug-InfiniteLoop/Bug-ExceptionHandling/Bug-MutableDefault/Bug-WrongOperator/Bug-DeadCode/Bug-TypeMismatch"
        }}
    ],
    "overall_score": "A|B|C|D|F",
    "summary": "One sentence covering both security and bug findings"
}}

STRICT RULES:
- issue_type is REQUIRED on every single item — never leave it out
- Every bug MUST have issue_type="BUG" and category starting with "Bug-"
- Every security issue MUST have issue_type="SECURITY"
- Find ALL bugs — do not skip division by zero, file leaks, off-by-one
- Respond ONLY with valid JSON"""


LIVE_REVIEW_PROMPT = """You are KavachAI, reviewing {language} code for security issues AND bugs.

Code:
```
{code}
```

Return a JSON array (max 10 items):
[
    {{
        "line": <line number>,
        "severity": "critical|high|medium|low",
        "message": "Start with [BUG] or [SECURITY] then brief description",
        "suggestion": "How to fix it"
    }}
]

Respond ONLY with valid JSON."""


REPO_ANALYSIS_PROMPT = """You are KavachAI, analyzing a repository file for security vulnerabilities AND bugs.

File: {file_path}
Language: {language}
Code:
```
{code}
```

Find ALL security vulnerabilities AND ALL bugs. For every bug set issue_type="BUG" and prefix category with "Bug-".

Respond with JSON:
{{
    "vulnerabilities": [
        {{
            "title": "Short title",
            "severity": "critical|high|medium|low",
            "line_number": <line number or null>,
            "description": "What is wrong and why",
            "fix_suggestion": "Corrected code",
            "issue_type": "SECURITY|BUG",
            "category": "Injection|Bug-ZeroDivision|Bug-ResourceLeak|Bug-OffByOne|..."
        }}
    ],
    "file_score": "A|B|C|D|F"
}}

Respond ONLY with valid JSON."""


class GeminiService:
    def __init__(self):
        self.client: Optional[genai.Client] = None
        self._initialized = False

    def _ensure_client(self):
        if not self._initialized:
            if settings.GEMINI_API_KEY:
                try:
                    self.client = genai.Client(api_key=settings.GEMINI_API_KEY)
                    self._initialized = True
                    logger.info("Gemini client initialized")
                except Exception as e:
                    logger.error(f"Failed to initialize Gemini client: {e}")
                    self._initialized = True
            else:
                logger.warning("No GEMINI_API_KEY — AI analysis disabled")
                self._initialized = True

    @property
    def is_available(self) -> bool:
        return self.client is not None

    async def analyze_vulnerabilities(self, code: str, language: str) -> dict:
        self._ensure_client()
        if not self.client:
            return {"vulnerabilities": [], "overall_score": "N/A", "summary": "Gemini API not configured"}
        prompt = VULNERABILITY_ANALYSIS_PROMPT.format(language=language, code=code)
        return await self._generate_json(prompt)

    async def live_review(self, code: str, language: str) -> list:
        self._ensure_client()
        if not self.client:
            return []
        prompt = LIVE_REVIEW_PROMPT.format(language=language, code=code)
        result = await self._generate_json(prompt)
        if isinstance(result, list):
            return result
        return result.get("issues", [])

    async def analyze_repo_file(self, code: str, language: str, file_path: str) -> dict:
        self._ensure_client()
        if not self.client:
            return {"vulnerabilities": [], "file_score": "N/A"}
        prompt = REPO_ANALYSIS_PROMPT.format(language=language, code=code, file_path=file_path)
        return await self._generate_json(prompt)

    async def _generate_json(self, prompt: str) -> dict | list:
        try:
            response = self.client.models.generate_content(
                model="gemini-1.5-flash-latest",
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.1,
                    max_output_tokens=4096,
                ),
            )
            text = response.text.strip()

            # Strip markdown fences
            if text.startswith("```"):
                lines = text.split("\n")
                text = "\n".join(lines[1:])
                if text.endswith("```"):
                    text = text[:-3]
                text = text.strip()

            return json.loads(text)

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Gemini JSON: {e}")
            return {"vulnerabilities": [], "error": "Failed to parse AI response"}
        except Exception as e:
            logger.error(f"Gemini API error: {e}")
            return {"vulnerabilities": [], "error": str(e)}


gemini_service = GeminiService()