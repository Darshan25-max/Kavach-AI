import re
import hashlib
import logging
from dataclasses import dataclass
from typing import Optional
from app.utils.parsers import detect_language, extract_code_snippet
from app.utils.rules import SecurityRule, SECURITY_RULES, get_rules_by_language

logger = logging.getLogger(__name__)


@dataclass
class DetectedVulnerability:
    rule: SecurityRule
    line_number: int
    matched_text: str
    code_snippet: str


# ── Hardcoded bug rules ───────────────────────────────────────────────────────
# These catch common bugs that Gemini sometimes misses or mislabels.

@dataclass
class BugRule:
    id: str
    name: str
    description: str
    severity: str
    pattern: str
    category: str
    fix_suggestion: str


BUG_RULES = [
    BugRule(
        id="BUG-001",
        name="Division By Zero Risk",
        description="Division operation with no zero check on the divisor. Will raise ZeroDivisionError at runtime if divisor is 0.",
        severity="high",
        pattern=r"(\w+)\s*/\s*(\w+)\s*(?!\s*==\s*0|\s*!=\s*0)",
        category="Bug-ZeroDivision",
        fix_suggestion="Add a zero check before dividing:\nif b != 0:\n    return a / b\nelse:\n    raise ValueError('Divisor cannot be zero')",
    ),
    BugRule(
        id="BUG-002",
        name="File Handle Leak",
        description="File opened with open() without a context manager (with statement). If an exception occurs, the file will never be closed.",
        severity="medium",
        pattern=r"(?<!\bwith\b.{0,50})\b(\w+)\s*=\s*open\s*\(",
        category="Bug-ResourceLeak",
        fix_suggestion="Use a context manager:\nwith open(path) as f:\n    return f.read()",
    ),
    BugRule(
        id="BUG-003",
        name="Off-By-One Error in Loop",
        description="Loop uses range(len(x) - 1) which skips the last element of the list.",
        severity="medium",
        pattern=r"range\s*\(\s*len\s*\([^)]+\)\s*-\s*1\s*\)",
        category="Bug-OffByOne",
        fix_suggestion="Use range(len(items)) to include all elements:\nfor i in range(len(items)):\n    if items[i] == target:\n        return i",
    ),
    BugRule(
        id="BUG-004",
        name="Empty List Division Risk",
        description="sum() divided by len() with no check for empty list. Raises ZeroDivisionError if the list is empty.",
        severity="high",
        pattern=r"sum\s*\([^)]+\)\s*/\s*len\s*\([^)]+\)",
        category="Bug-ZeroDivision",
        fix_suggestion="Check for empty list first:\nif not numbers:\n    return 0\nreturn sum(numbers) / len(numbers)",
    ),
    BugRule(
        id="BUG-005",
        name="Mutable Default Argument",
        description="Using a mutable object (list, dict, set) as a default argument. The same object is shared across all calls.",
        severity="medium",
        pattern=r"def\s+\w+\s*\([^)]*=\s*(\[\]|\{\}|set\(\))[^)]*\)",
        category="Bug-MutableDefault",
        fix_suggestion="Use None as default and create inside function:\ndef func(items=None):\n    if items is None:\n        items = []",
    ),
    BugRule(
        id="BUG-006",
        name="Bare Exception Catch",
        description="Catching all exceptions with 'except:' or 'except Exception:' hides real errors and makes debugging impossible.",
        severity="low",
        pattern=r"except\s*:",
        category="Bug-ExceptionHandling",
        fix_suggestion="Catch specific exceptions:\nexcept ValueError as e:\n    logger.error(f'Error: {e}')",
    ),
    BugRule(
        id="BUG-007",
        name="Unreachable Code After Return",
        description="Code exists after a return statement and will never be executed.",
        severity="low",
        pattern=r"return\s+.+\n\s+(?!def|class|#|return|else|elif|except|finally)\w+",
        category="Bug-DeadCode",
        fix_suggestion="Remove or move the unreachable code before the return statement.",
    ),
]

# Only apply bug rules to these languages
BUG_RULE_LANGUAGES = {"python", "py", "text"}


def run_regex_scan(code: str, language: Optional[str] = None) -> list[DetectedVulnerability]:
    """Run regex-based security pattern matching against the code."""
    detected = []

    if language:
        rules = get_rules_by_language(language)
    else:
        rules = SECURITY_RULES

    for rule in rules:
        try:
            for match in re.finditer(rule.pattern, code, re.IGNORECASE | re.DOTALL):
                line_number = code[:match.start()].count("\n") + 1
                snippet = extract_code_snippet(code, line_number)
                detected.append(DetectedVulnerability(
                    rule=rule,
                    line_number=line_number,
                    matched_text=match.group(0)[:200],
                    code_snippet=snippet,
                ))
        except re.error as e:
            logger.warning(f"Regex error in rule {rule.id}: {e}")
            continue

    return detected


def run_bug_scan(code: str, language: Optional[str] = None) -> list[dict]:
    """
    Run hardcoded bug detection rules.
    Returns list of dicts ready to be saved as Vulnerability records.
    """
    lang = (language or "").lower()
    if lang not in BUG_RULE_LANGUAGES and lang != "":
        # Only skip if language is explicitly a non-Python language
        non_python = {"javascript", "typescript", "java", "go", "rust", "php",
                      "ruby", "csharp", "c", "cpp", "sql", "bash", "swift", "kotlin"}
        if lang in non_python:
            return []

    bugs = []
    seen_lines = set()

    for rule in BUG_RULES:
        try:
            for match in re.finditer(rule.pattern, code, re.IGNORECASE | re.MULTILINE):
                line_number = code[:match.start()].count("\n") + 1

                # Skip duplicates on same line
                key = (rule.id, line_number)
                if key in seen_lines:
                    continue
                seen_lines.add(key)

                # Extract snippet around the bug
                lines = code.split("\n")
                start = max(0, line_number - 2)
                end = min(len(lines), line_number + 1)
                snippet = "\n".join(
                    f"{i+1}: {lines[i]}" for i in range(start, end)
                )

                bugs.append({
                    "title": rule.name,
                    "description": rule.description,
                    "severity": rule.severity,
                    "line_number": line_number,
                    "code_snippet": snippet,
                    "fix_suggestion": rule.fix_suggestion,
                    "cwe_id": None,
                    "category": rule.category,
                    "issue_type": "BUG",
                })
        except re.error as e:
            logger.warning(f"Bug rule regex error {rule.id}: {e}")
            continue

    return bugs


def compute_code_hash(code: str) -> str:
    """Compute SHA-256 hash of the code for deduplication."""
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def detect_language_safe(code: str, requested_language: Optional[str] = None) -> str:
    """Detect language with fallback."""
    if requested_language and requested_language.lower() != "auto":
        return requested_language.lower()
    detected = detect_language(code)
    return detected if detected != "unknown" else "text"