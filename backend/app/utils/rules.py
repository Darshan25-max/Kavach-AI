from dataclasses import dataclass
from typing import Optional


@dataclass
class SecurityRule:
    id: str
    name: str
    category: str
    severity: str  # critical, high, medium, low
    pattern: str  # regex pattern
    description: str
    cwe_id: Optional[str] = None
    languages: Optional[list[str]] = None  # None = applies to all


# Comprehensive security rules database
SECURITY_RULES: list[SecurityRule] = [
    # === INJECTION ===
    SecurityRule(
        id="INJ-SQL-001",
        name="SQL Injection - String Concatenation",
        category="Injection",
        severity="critical",
        pattern=r"(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|UNION).*\+\s*(req|request|params|query|body|input|user)",
        description="SQL query constructed with string concatenation using user input. Use parameterized queries instead.",
        cwe_id="CWE-89",
        languages=["python", "javascript", "java", "php", "ruby"],
    ),
    SecurityRule(
        id="INJ-SQL-002",
        name="SQL Injection - f-string / format",
        category="Injection",
        severity="critical",
        pattern=r"(?i)(execute|cursor\.execute)\s*\(\s*[fr]?(\"|\').*(SELECT|INSERT|UPDATE|DELETE|DROP|UNION).*\{",
        description="SQL query uses f-string or format() with potentially unsafe input. Use parameterized queries.",
        cwe_id="CWE-89",
        languages=["python"],
    ),
    SecurityRule(
        id="INJ-SQL-003",
        name="SQL Injection - raw query with user input",
        category="Injection",
        severity="critical",
        pattern=r"(?i)\.raw\s*\(\s*[\"'].*\+.*(?:req|request|params|query|body)",
        description="Raw SQL query includes unsanitized user input. Use ORM or parameterized queries.",
        cwe_id="CWE-89",
    ),
    SecurityRule(
        id="INJ-CMD-001",
        name="Command Injection - os.system",
        category="Injection",
        severity="critical",
        pattern=r"(?i)(os\.system|os\.popen|subprocess\.call|subprocess\.run|subprocess\.Popen)\s*\([^)]*(req|request|input|user|params|query)",
        description="Operating system command executed with user input. Use subprocess with shell=False and argument lists.",
        cwe_id="CWE-78",
        languages=["python"],
    ),
    SecurityRule(
        id="INJ-CMD-002",
        name="Command Injection - exec/eval",
        category="Injection",
        severity="critical",
        pattern=r"(?i)\b(exec|eval)\s*\(\s*(req|request|input|user|params|query|body)",
        description="Code execution function called with user-supplied input. Avoid eval/exec with untrusted data.",
        cwe_id="CWE-94",
        languages=["python", "javascript"],
    ),
    SecurityRule(
        id="INJ-LDAP-001",
        name="LDAP Injection",
        category="Injection",
        severity="high",
        pattern=r"(?i)ldap\.(search|bind|sasl_bind)\s*\([^)]*(req|request|input|user|params|query)",
        description="LDAP query constructed with user input. Sanitize and escape LDAP special characters.",
        cwe_id="CWE-90",
    ),

    # === XSS ===
    SecurityRule(
        id="XSS-REF-001",
        name="Reflected XSS - innerHTML",
        category="XSS",
        severity="high",
        pattern=r"(?i)\.innerHTML\s*=\s*(req|request|params|query|location|document\.URL|document\.referrer)",
        description="User input directly assigned to innerHTML. Use textContent or sanitize with DOMPurify.",
        cwe_id="CWE-79",
        languages=["javascript"],
    ),
    SecurityRule(
        id="XSS-REF-002",
        name="Reflected XSS - document.write",
        category="XSS",
        severity="high",
        pattern=r"(?i)document\.write\s*\([^)]*(req|request|params|query|location)",
        description="User input passed to document.write. Use DOM manipulation methods instead.",
        cwe_id="CWE-79",
        languages=["javascript"],
    ),
    SecurityRule(
        id="XSS-DOM-001",
        name="DOM-based XSS - location source",
        category="XSS",
        severity="high",
        pattern=r"(?i)(location\.hash|location\.search|location\.href).*\.(innerHTML|outerHTML|document\.write)",
        description="DOM source flows into dangerous sink. Validate and sanitize all DOM inputs.",
        cwe_id="CWE-79",
        languages=["javascript"],
    ),
    SecurityRule(
        id="XSS-STORED-001",
        name="Stored XSS - unescaped output",
        category="XSS",
        severity="high",
        pattern=r"(?i)(\|\s*safe|markSafe|Markup|\.safe)\s*\(",
        description="Content marked as safe without proper sanitization. Verify the content is actually safe.",
        cwe_id="CWE-79",
        languages=["python"],
    ),

    # === AUTHENTICATION ===
    SecurityRule(
        id="AUTH-HCRED-001",
        name="Hardcoded Credentials - Password",
        category="Authentication",
        severity="critical",
        pattern=r"(?i)(password|passwd|pwd|secret|api_key|apikey|token)\s*[:=]\s*[\"'][^\"']{4,}[\"']",
        description="Hardcoded credential detected. Use environment variables or a secrets manager.",
        cwe_id="CWE-798",
    ),
    SecurityRule(
        id="AUTH-HCRED-002",
        name="Hardcoded Credentials - Database Connection",
        category="Authentication",
        severity="critical",
        pattern=r"(?i)(mysql|postgres|mongodb|redis)://\w+:\w+@",
        description="Database connection string with hardcoded credentials. Use environment variables.",
        cwe_id="CWE-798",
    ),
    SecurityRule(
        id="AUTH-WEAK-001",
        name="Weak Session Configuration",
        category="Authentication",
        severity="medium",
        pattern=r"(?i)(session|cookie).*\b(secure\s*=\s*false|httponly\s*=\s*false|samesite\s*=\s*none)",
        description="Weak session/cookie configuration detected. Set secure, httpOnly, and sameSite flags.",
        cwe_id="CWE-614",
    ),
    SecurityRule(
        id="AUTH-BYPASS-001",
        name="Authentication Bypass - Disabled Auth",
        category="Authentication",
        severity="critical",
        pattern=r"(?i)(@app\.route|router)\s*.\n.*(?:auth|login|verify)\s*[:=]\s*(False|None|off|disabled)",
        description="Authentication check explicitly disabled. Never disable auth in production code.",
        cwe_id="CWE-306",
    ),

    # === CRYPTOGRAPHY ===
    SecurityRule(
        id="CRYPTO-WEAK-001",
        name="Weak Hashing Algorithm",
        category="Cryptography",
        severity="high",
        pattern=r"(?i)(hashlib\.(md5|sha1)|MD5|SHA1|md5\(|sha1\()",
        description="Weak hashing algorithm detected. Use SHA-256 or stronger for security-sensitive operations.",
        cwe_id="CWE-328",
    ),
    SecurityRule(
        id="CRYPTO-WEAK-002",
        name="Weak Encryption Algorithm",
        category="Cryptography",
        severity="high",
        pattern=r"(?i)(DES|RC4|Blowfish|AES.*ECB|cipher\.MODE_ECB)",
        description="Weak or insecure encryption algorithm/mode detected. Use AES-GCM or ChaCha20-Poly1305.",
        cwe_id="CWE-327",
    ),
    SecurityRule(
        id="CRYPTO-HKEY-001",
        name="Hardcoded Encryption Key",
        category="Cryptography",
        severity="critical",
        pattern=r"(?i)(encryption_key|secret_key|aes_key|private_key)\s*[:=]\s*[\"'][^\"']+[\"']",
        description="Hardcoded encryption key detected. Store keys in environment variables or key management services.",
        cwe_id="CWE-321",
    ),
    SecurityRule(
        id="CRYPTO-RAND-001",
        name="Insecure Random Number Generator",
        category="Cryptography",
        severity="medium",
        pattern=r"(?i)(Math\.random|random\.random|random\.randint)\s*\(.*(?:token|password|secret|key|session)",
        description="Insecure random number generator used for security-sensitive purpose. Use secrets module or crypto.getRandomValues.",
        cwe_id="CWE-338",
    ),

    # === CONFIGURATION ===
    SecurityRule(
        id="CONFIG-DEBUG-001",
        name="Debug Mode Enabled",
        category="Configuration",
        severity="high",
        pattern=r"(?i)(DEBUG\s*=\s*True|debug\s*:\s*true|app\.debug\s*=\s*True|NODE_ENV\s*=\s*development)",
        description="Debug mode enabled in configuration. Disable in production environments.",
        cwe_id="CWE-489",
    ),
    SecurityRule(
        id="CONFIG-CORS-001",
        name="Overly Permissive CORS",
        category="Configuration",
        severity="high",
        pattern=r"(?i)(CORS|cors).*\*|allow_origins\s*=\s*\[?\s*[\"']\*[\"']",
        description="Wildcard CORS configuration detected. Restrict to specific trusted origins.",
        cwe_id="CWE-942",
    ),
    SecurityRule(
        id="CONFIG-SSL-001",
        name="SSL Verification Disabled",
        category="Configuration",
        severity="high",
        pattern=r"(?i)(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|ssl_verifypeer\s*=\s*0|InsecureRequestWarning)",
        description="SSL/TLS certificate verification disabled. Always verify certificates in production.",
        cwe_id="CWE-295",
    ),
    SecurityRule(
        id="CONFIG-EXPOSE-001",
        name="Sensitive Information Exposure - Stack Trace",
        category="Configuration",
        severity="medium",
        pattern=r"(?i)(traceback|stack.?trace|error.*details).*\b(return|response|send|write|print)",
        description="Detailed error information may be exposed to users. Use generic error messages in production.",
        cwe_id="CWE-209",
    ),

    # === DATA PROTECTION ===
    SecurityRule(
        id="DATA-SENS-001",
        name="Sensitive Data in Logs",
        category="Data Protection",
        severity="high",
        pattern=r"(?i)(log|logger|console\.log|print).*\b(password|credit.?card|ssn|social.?security|token|secret)\b",
        description="Sensitive data may be logged. Mask or exclude sensitive fields from log output.",
        cwe_id="CWE-532",
    ),
    SecurityRule(
        id="DATA-DESER-001",
        name="Insecure Deserialization",
        category="Data Protection",
        severity="critical",
        pattern=r"(?i)(pickle\.loads?|yaml\.load\s*\(|marshal\.loads?|unserialize\s*\()(?!.*SafeLoader)",
        description="Insecure deserialization detected. Use safe alternatives like json.loads or yaml.safe_load.",
        cwe_id="CWE-502",
        languages=["python", "php"],
    ),
    SecurityRule(
        id="DATA-SENS-002",
        name="Sensitive Data in URL",
        category="Data Protection",
        severity="medium",
        pattern=r"(?i)(GET|fetch|axios\.get|requests\.get)\s*\([^)]*\b(password|token|secret|api_key|apikey)\b",
        description="Sensitive data passed in URL parameters. Use POST requests with body for sensitive data.",
        cwe_id="CWE-598",
    ),

    # === PATH TRAVERSAL ===
    SecurityRule(
        id="PATH-TRAVERSAL-001",
        name="Path Traversal",
        category="Path Traversal",
        severity="high",
        pattern=r"(?i)(open|read|write|file|os\.path)\s*\([^)]*(req|request|input|user|params|query)",
        description="File operation with user-controlled path. Validate and sanitize file paths.",
        cwe_id="CWE-22",
    ),

    # === SSRF ===
    SecurityRule(
        id="SSRF-001",
        name="Server-Side Request Forgery",
        category="SSRF",
        severity="high",
        pattern=r"(?i)(requests\.(get|post)|fetch|urllib|http\.client)\s*\([^)]*(req|request|input|user|params|query|url)",
        description="HTTP request made with user-controlled URL. Validate and restrict allowed destinations.",
        cwe_id="CWE-918",
    ),

    # === XXE ===
    SecurityRule(
        id="XXE-001",
        name="XML External Entity Injection",
        category="XXE",
        severity="high",
        pattern=r"(?i)(xml\.etree|lxml|xml\.dom|DocumentBuilder|SAXParser).*parse\s*\((?!.*disallow)",
        description="XML parsing without entity restrictions. Disable external entities and DTD processing.",
        cwe_id="CWE-611",
    ),

    # === UNSAFE REDIRECT ===
    SecurityRule(
        id="REDIRECT-001",
        name="Open Redirect",
        category="Redirect",
        severity="medium",
        pattern=r"(?i)(redirect|response\.redirect|res\.redirect)\s*\(\s*(req|request|params|query)\.",
        description="Redirect with user-controlled URL. Validate redirect destinations against an allowlist.",
        cwe_id="CWE-601",
    ),
]


def get_rules_by_category(category: str) -> list[SecurityRule]:
    return [r for r in SECURITY_RULES if r.category.lower() == category.lower()]


def get_rules_by_severity(severity: str) -> list[SecurityRule]:
    return [r for r in SECURITY_RULES if r.severity.lower() == severity.lower()]


def get_rules_by_language(language: str) -> list[SecurityRule]:
    lang = language.lower()
    return [
        r for r in SECURITY_RULES
        if r.languages is None or lang in [l.lower() for l in r.languages]
    ]


def get_all_categories() -> list[str]:
    return sorted(set(r.category for r in SECURITY_RULES))
