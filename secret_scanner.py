"""
Scans JS file content for hardcoded secrets, weak crypto, sensitive
endpoints, exposed source maps, and other "juice" (analytics IDs, Sentry
DSNs, emails, feature flags), using the pattern database in
secret_patterns.py.
"""
import re
from urllib.parse import urljoin

import requests

from secret_patterns import (
    SECRET_PATTERNS,
    WEAK_CRYPTO_PATTERNS,
    HARDCODED_CRYPTO_KEY_PATTERN,
    RISKY_COMMENT_KEYWORDS,
    ENDPOINT_PATTERN,
    INTERNAL_HINT_KEYWORDS,
    CLOUD_STORAGE_PATTERN,
    API_SCHEMA_ENDPOINT_PATTERN,
    WEBSOCKET_URL_PATTERN,
    SOURCE_MAP_PATTERN,
    SENTRY_DSN_PATTERN,
    ANALYTICS_ID_PATTERNS,
    EMAIL_PATTERN,
    FEATURE_FLAG_KEYWORDS,
)

LINE_COMMENT = re.compile(r"//(.*)")
BLOCK_COMMENT = re.compile(r"/\*(.*?)\*/", re.DOTALL)


def _mask(secret: str) -> str:
    """Mask a found secret so raw output doesn't leak the full value."""
    if len(secret) <= 8:
        return "*" * len(secret)
    return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]


def find_secrets(content: str):
    findings = []
    for label, pattern in SECRET_PATTERNS:
        for m in pattern.finditer(content):
            value = m.group(1) if m.groups() else m.group(0)
            findings.append({"type": label, "match": _mask(value)})
    return findings


def find_weak_crypto(content: str):
    """Returns list of {type, context} for weak/broken crypto usage."""
    findings = []
    for label, pattern in WEAK_CRYPTO_PATTERNS:
        m = pattern.search(content)
        if m:
            start = max(0, m.start() - 30)
            end = min(len(content), m.end() + 30)
            findings.append({"type": label, "context": content[start:end].strip().replace("\n", " ")})
    return findings


def find_hardcoded_crypto_keys(content: str):
    """Returns list of masked literals found suspiciously close to a crypto call."""
    findings = []
    for m in HARDCODED_CRYPTO_KEY_PATTERN.finditer(content):
        findings.append({"match": _mask(m.group(1))})
    return findings


def find_risky_comments(content: str):
    comments = []
    for pattern in (LINE_COMMENT, BLOCK_COMMENT):
        for m in pattern.finditer(content):
            text = m.group(1).strip()
            if not text:
                continue
            lowered = text.lower()
            if any(kw in lowered for kw in RISKY_COMMENT_KEYWORDS):
                comments.append(text[:200])
    return comments


def find_endpoints(content: str):
    endpoints = []
    seen = set()
    for m in ENDPOINT_PATTERN.finditer(content):
        url = m.group(1)
        if url in seen:
            continue
        seen.add(url)
        lowered = url.lower()
        flagged = any(kw in lowered for kw in INTERNAL_HINT_KEYWORDS)
        endpoints.append({"url": url, "flagged_internal": flagged})
    return endpoints


def find_cloud_storage_refs(content: str):
    return sorted(set(m.group(1) for m in CLOUD_STORAGE_PATTERN.finditer(content)))


def find_api_schema_endpoints(content: str):
    return sorted(set(m.group(1) for m in API_SCHEMA_ENDPOINT_PATTERN.finditer(content)))


def find_websocket_urls(content: str):
    return sorted(set(m.group(1) for m in WEBSOCKET_URL_PATTERN.finditer(content)))


def find_sentry_dsn(content: str):
    m = SENTRY_DSN_PATTERN.search(content)
    return m.group(0) if m else None


def find_analytics_ids(content: str):
    findings = []
    for label, pattern in ANALYTICS_ID_PATTERNS:
        m = pattern.search(content)
        if m:
            value = m.group(1) if m.groups() else m.group(0)
            findings.append({"type": label, "value": value})
    return findings


def find_emails(content: str, limit: int = 20):
    emails = sorted(set(EMAIL_PATTERN.findall(content)))
    return emails[:limit]


def find_feature_flags(content: str):
    found = set()
    lowered = content.lower()
    for kw in FEATURE_FLAG_KEYWORDS:
        if kw in lowered:
            found.add(kw)
    return sorted(found)


def check_source_map(js_url: str, content: str, session: requests.Session = None, timeout: int = 8):
    match = SOURCE_MAP_PATTERN.search(content)
    if not match:
        return None

    map_ref = match.group(1)
    if map_ref.startswith("data:"):
        return {"map_url": "(inline data URI, not a separate exposed file)", "accessible": False}

    map_url = urljoin(js_url, map_ref)
    sess = session or requests.Session()
    try:
        resp = sess.get(map_url, timeout=timeout)
        accessible = resp.status_code == 200 and len(resp.content) > 0
    except requests.RequestException:
        accessible = False

    return {"map_url": map_url, "accessible": accessible}


def scan_js_file(url: str, content: str, session: requests.Session = None):
    """Runs every check against a single JS file's content."""
    return {
        "url": url,
        "secrets": find_secrets(content),
        "weak_crypto": find_weak_crypto(content),
        "hardcoded_crypto_keys": find_hardcoded_crypto_keys(content),
        "risky_comments": find_risky_comments(content),
        "endpoints": find_endpoints(content),
        "cloud_storage": find_cloud_storage_refs(content),
        "api_schema_endpoints": find_api_schema_endpoints(content),
        "websocket_urls": find_websocket_urls(content),
        "sentry_dsn": find_sentry_dsn(content),
        "analytics_ids": find_analytics_ids(content),
        "emails": find_emails(content),
        "feature_flags": find_feature_flags(content),
        "source_map": check_source_map(url, content, session=session),
    }


def has_findings(result: dict) -> bool:
    return bool(
        result["secrets"] or result["weak_crypto"] or result["hardcoded_crypto_keys"]
        or result["risky_comments"] or result["cloud_storage"] or result["api_schema_endpoints"]
        or result["websocket_urls"] or result["sentry_dsn"] or result["analytics_ids"]
        or result["feature_flags"]
        or (result["source_map"] and result["source_map"]["accessible"])
        or any(e["flagged_internal"] for e in result["endpoints"])
    )
