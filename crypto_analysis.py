"""
Detects encryption/hashing usage in JS source: which crypto library is
being used, which algorithms, what mode (if determinable), and pulls the
surrounding code so it can be reviewed by a human rather than just
flagged as a pass/fail.

Honest limitation: for minified/production JS, cleanly extracting "the
enclosing function" isn't reliable without a real JS parser. Instead we
grab a wider context window of raw characters around each match — good
enough to show *what's happening*, even if it's not perfectly formatted.
"""
import re

# Which crypto library/API is in use
LIBRARY_PATTERNS = [
    ("CryptoJS", re.compile(r"\bCryptoJS\b")),
    ("Web Crypto API (SubtleCrypto)", re.compile(r"\bcrypto\.subtle\.")),
    ("node-forge", re.compile(r"\bforge\.(?:pki|cipher|md|random)\b")),
    ("JSEncrypt", re.compile(r"\bJSEncrypt\b")),
    ("bcryptjs", re.compile(r"\bbcrypt\.(?:hash|compare|genSalt)\b", re.IGNORECASE)),
    ("jsonwebtoken / jwt-decode", re.compile(r"\bjwt_decode\b|jsonwebtoken")),
    ("elliptic (ECC library)", re.compile(r"\belliptic\b")),
]

# (algorithm label, regex, classification) — classification is a quick
# "is this considered okay by modern standards" signal, not a full audit
ALGORITHM_PATTERNS = [
    ("AES", re.compile(r"\bAES\b"), "generally strong (mode/key-size dependent)"),
    ("3DES / DES", re.compile(r"\b(?:Triple)?DES\b|\b3DES\b"), "weak — deprecated"),
    ("RC4", re.compile(r"\bRC4\b"), "broken — do not use"),
    ("RSA", re.compile(r"\bRSA\b"), "strong if key size >= 2048-bit"),
    ("ECDSA / ECDH (elliptic curve)", re.compile(r"\bECDSA\b|\bECDH\b"), "strong"),
    ("MD5", re.compile(r"\bMD5\b"), "weak hash — collision-prone"),
    ("SHA-1", re.compile(r"\bSHA-?1\b"), "weak hash — deprecated for security use"),
    ("SHA-256/384/512", re.compile(r"\bSHA-?(?:256|384|512)\b"), "strong hash"),
    ("HMAC", re.compile(r"\bHMAC\b"), "strong (for integrity/auth)"),
    ("PBKDF2", re.compile(r"\bPBKDF2\b"), "acceptable for password hashing"),
    ("bcrypt", re.compile(r"\bbcrypt\b", re.IGNORECASE), "good for password hashing"),
    ("Base64 (encoding, NOT encryption)", re.compile(r"\batob\(|\bbtoa\(|Base64\.(?:encode|decode)"), "not encryption — often mistaken for it"),
]

MODE_PATTERN = re.compile(r"\b(CBC|ECB|GCM|CTR|CFB|OFB)\b")


def _context(content: str, start: int, end: int, window: int = 120) -> str:
    """Grabs a readable snippet of code around a match, collapsed to one line."""
    lo = max(0, start - window)
    hi = min(len(content), end + window)
    snippet = content[lo:hi]
    snippet = re.sub(r"\s+", " ", snippet).strip()
    return snippet


def _statement_window(content: str, start: int, end: int, max_window: int = 150) -> str:
    """
    Grabs the surrounding JS statement (bounded by the nearest ';' on
    each side, capped at max_window) rather than a fixed character count —
    this avoids pulling in details from a *different*, nearby statement
    (e.g. one algorithm's mode leaking into another's).
    """
    lo_bound = max(0, start - max_window)
    hi_bound = min(len(content), end + max_window)

    prev_semi = content.rfind(";", lo_bound, start)
    lo = prev_semi + 1 if prev_semi != -1 else lo_bound

    next_semi = content.find(";", end, hi_bound)
    hi = next_semi if next_semi != -1 else hi_bound

    return content[lo:hi]


def analyze_crypto_usage(url: str, content: str):
    """
    Returns a dict summarizing all crypto/encryption usage found in this
    file, or None if nothing crypto-related was detected at all.
    """
    libraries = []
    for label, pattern in LIBRARY_PATTERNS:
        if pattern.search(content):
            libraries.append(label)

    algorithms = []
    for label, pattern, classification in ALGORITHM_PATTERNS:
        matches = list(pattern.finditer(content))
        if not matches:
            continue

        occurrences = []
        seen_modes = set()
        for m in matches[:10]:  # cap scanning to avoid pathological files
            statement = _statement_window(content, m.start(), m.end())
            mode_match = MODE_PATTERN.search(statement)
            mode = mode_match.group(1) if mode_match else None

            # keep occurrences that introduce a NEW mode (or the first
            # occurrence even with no mode) — avoids dumping 10 near-
            # identical entries when a file calls the same thing repeatedly
            if mode in seen_modes and len(occurrences) > 0:
                continue
            seen_modes.add(mode)

            occurrences.append({
                "mode": mode,
                "context": _context(content, m.start(), m.end()),
            })
            if len(occurrences) >= 3:  # cap distinct occurrences shown
                break

        algorithms.append({
            "algorithm": label,
            "classification": classification,
            "total_occurrences": len(matches),
            "occurrences": occurrences,
        })

    if not libraries and not algorithms:
        return None

    return {
        "url": url,
        "libraries": libraries,
        "algorithms": algorithms,
    }


def analyze_all(contents: dict):
    """contents: {url: content}. Returns list of per-file crypto reports (non-empty only)."""
    results = []
    for url, content in contents.items():
        result = analyze_crypto_usage(url, content)
        if result:
            results.append(result)
    return results
