"""
Queries the OSV.dev API (https://osv.dev) for known vulnerabilities affecting
a given npm package name + version. No API key required.
"""
import requests

OSV_API_URL = "https://api.osv.dev/v1/query"


def check_package(name: str, version: str, timeout: int = 10):
    """
    Returns a list of vulnerability dicts: [{id, summary, severity, ...}, ...]
    if the check succeeded and found nothing.
    Returns None if the check itself FAILED (network error, non-200, etc.) —
    this is intentionally distinct from an empty list, so callers don't
    mistake "couldn't check" for "checked and it's clean".
    """
    payload = {
        "version": version,
        "package": {"name": name, "ecosystem": "npm"},
    }
    try:
        resp = requests.post(OSV_API_URL, json=payload, timeout=timeout)
        if resp.status_code != 200:
            return None
        data = resp.json()
        vulns = data.get("vulns", [])
        results = []
        for v in vulns:
            severity = "UNKNOWN"
            if v.get("severity"):
                severity = v["severity"][0].get("score", "UNKNOWN")
            elif v.get("database_specific", {}).get("severity"):
                severity = v["database_specific"]["severity"]

            summary = v.get("summary") or v.get("details", "")[:200] or "No summary available"
            results.append({
                "id": v.get("id", "UNKNOWN"),
                "summary": summary,
                "severity": severity,
                "link": f"https://osv.dev/vulnerability/{v.get('id', '')}",
            })
        return results
    except requests.RequestException:
        return None
