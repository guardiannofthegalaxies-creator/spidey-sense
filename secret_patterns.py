"""
Regex patterns for detecting hardcoded secrets, weak crypto usage, and
sensitive/interesting data inside JavaScript source. Adapted from public
secret-scanning signatures (similar in spirit to Gitleaks/TruffleHog/
SecretFinder), tuned to keep false positives reasonably low.
"""
import re

# ---------------------------------------------------------------------------
# 1. HARDCODED SECRETS / API KEYS
# ---------------------------------------------------------------------------
SECRET_PATTERNS = [
    ("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Firebase DB URL", re.compile(r"[a-z0-9-]+\.firebaseio\.com")),
    ("Stripe Live Secret Key", re.compile(r"sk_live_[0-9a-zA-Z]{20,}")),
    ("Stripe Live Publishable Key", re.compile(r"pk_live_[0-9a-zA-Z]{20,}")),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,48}")),
    ("Twilio API Key", re.compile(r"SK[0-9a-fA-F]{32}")),
    ("Mailgun API Key", re.compile(r"key-[0-9a-zA-Z]{32}")),
    ("SendGrid API Key", re.compile(r"SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}")),
    ("GitHub Personal Access Token", re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}")),
    ("Heroku API Key", re.compile(r"[hH]eroku[0-9A-Za-z_\-]{0,20}[\"']?\s*[:=]\s*[\"'][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[\"']")),
    ("Discord Bot Token", re.compile(r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}")),
    ("Telegram Bot Token", re.compile(r"\d{8,10}:[A-Za-z0-9_-]{35}")),
    ("Private Key Block", re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("JWT Token", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    (
        "Database Connection String",
        re.compile(r"(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|jdbc:[a-z]+)://[^\s\"'<>]{6,200}", re.IGNORECASE),
    ),
    (
        "Basic Auth Credentials in URL",
        re.compile(r"https?://[^\s\"'<>/@]{2,40}:[^\s\"'<>/@]{2,40}@[^\s\"'<>]{4,100}"),
    ),
    (
        "Generic API Key/Secret Assignment",
        re.compile(
            r"""(?:api[_-]?key|apikey|secret|access[_-]?token|client[_-]?secret|auth[_-]?token)\s*[:=]\s*["']([0-9a-zA-Z\-_]{16,})["']""",
            re.IGNORECASE,
        ),
    ),
    (
        "Hardcoded Password Assignment",
        re.compile(r"""password\s*[:=]\s*["']([^"']{4,})["']""", re.IGNORECASE),
    ),
]

# ---------------------------------------------------------------------------
# 2. WEAK / BROKEN CRYPTOGRAPHY
# ---------------------------------------------------------------------------
# Flag references to algorithms considered weak/broken by modern standards.
# Word-boundaried and, where ambiguous (e.g. DES), required to appear near a
# crypto-ish context word to cut down on false positives.
WEAK_CRYPTO_PATTERNS = [
    ("MD5 (weak hash)", re.compile(r"\bMD5\b", re.IGNORECASE)),
    ("SHA1 (weak hash)", re.compile(r"\bSHA-?1\b", re.IGNORECASE)),
    ("RC4 (broken cipher)", re.compile(r"\bRC4\b")),
    (
        "DES (weak cipher)",
        re.compile(r"\b(?:createCipher(?:iv)?\s*\(\s*['\"]des|CryptoJS\.DES)\b", re.IGNORECASE),
    ),
    ("ECB mode (insecure block mode)", re.compile(r"\bECB\b")),
]

# A crypto call (encrypt/decrypt/cipher) with a short quoted literal nearby
# on the same line is a strong smell of a hardcoded key or IV.
HARDCODED_CRYPTO_KEY_PATTERN = re.compile(
    r"""(?:AES|DES|createCipheriv|createDecipheriv|CryptoJS\.\w+\.encrypt|CryptoJS\.\w+\.decrypt)"""
    r"""[^\n;]{0,60}["']([0-9a-zA-Z+/=_-]{8,64})["']""",
)

# ---------------------------------------------------------------------------
# 3. RISKY COMMENTS
# ---------------------------------------------------------------------------
RISKY_COMMENT_KEYWORDS = [
    "todo", "fixme", "hack", "backup", "temp password", "temp cred",
    "remove before prod", "hardcoded", "do not commit", "credentials",
    "internal only", "debug", "test account", "default password",
]

# ---------------------------------------------------------------------------
# 4. ENDPOINTS / INTERESTING URLS
# ---------------------------------------------------------------------------
ENDPOINT_PATTERN = re.compile(
    r"""["'](https?://[^\s"'<>]{4,200}|/[a-zA-Z0-9_\-/]+\.(?:php|aspx|jsp|action|json|do)\b[^\s"'<>]*)["']"""
)

INTERNAL_HINT_KEYWORDS = [
    "admin", "internal", "staging", "test", "debug", "localhost",
    "127.0.0.1", "192.168.", "10.0.", "backup", "config", "swagger",
    "actuator", "phpinfo", ".env",
]

CLOUD_STORAGE_PATTERN = re.compile(
    r"""["'](https?://[a-zA-Z0-9.\-_]*(?:s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com|storage\.googleapis\.com|blob\.core\.windows\.net)[^\s"'<>]*)["']"""
)

API_SCHEMA_ENDPOINT_PATTERN = re.compile(
    r"""["'](/[^\s"'<>]*(?:swagger(?:\.json|\.yaml)?|openapi\.(?:json|yaml)|graphql|api-docs)[^\s"'<>]*)["']""",
    re.IGNORECASE,
)

WEBSOCKET_URL_PATTERN = re.compile(r"""["'](wss?://[^\s"'<>]{4,200})["']""")

# ---------------------------------------------------------------------------
# 5. SOURCE MAPS
# ---------------------------------------------------------------------------
SOURCE_MAP_PATTERN = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")

# ---------------------------------------------------------------------------
# 6. MISC "JUICE": monitoring DSNs, analytics IDs, emails, feature flags
# ---------------------------------------------------------------------------
SENTRY_DSN_PATTERN = re.compile(
    r"https://[0-9a-f]{32}@[a-z0-9.\-]*\.ingest\.sentry\.io/[0-9]+"
)

ANALYTICS_ID_PATTERNS = [
    ("Google Analytics ID", re.compile(r"\bUA-\d{4,10}-\d{1,4}\b")),
    ("Google Analytics 4 ID", re.compile(r"\bG-[A-Z0-9]{6,10}\b")),
    ("Mixpanel Token (near context)", re.compile(r"mixpanel[^\n]{0,40}['\"]([0-9a-f]{32})['\"]", re.IGNORECASE)),
]

EMAIL_PATTERN = re.compile(r"(?<!//)(?<![\w./-])[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

FEATURE_FLAG_KEYWORDS = [
    "isadmin", "debugmode", "betafeature", "isbeta", "featureflag",
    "enabledebug", "adminmode", "testmode", "bypassauth", "skipauth",
]
