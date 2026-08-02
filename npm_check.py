"""
Checks npm's public registry for a package's latest published version, so we
can flag a detected library as "outdated" even when no specific CVE has been
filed against it yet (which is a different signal than OSV vulnerability
checks — old code can carry unpatched risk without a formal CVE existing).
"""
import re
from urllib.parse import quote

import requests

NPM_REGISTRY_URL = "https://registry.npmjs.org/{package}/latest"


def _parse_version(v: str):
    """
    Parses a 'x.y.z' style version string into a tuple of ints for
    comparison. Strips any pre-release/build suffix (e.g. '1.2.3-beta.1'
    becomes (1, 2, 3)). Returns None if it doesn't look like a version.
    """
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", v)
    if not match:
        return None
    return tuple(int(x) for x in match.groups())


def get_latest_version(package_name: str, timeout: int = 8):
    """
    Returns the latest published version string for a package on npm,
    or None if the package isn't found / registry is unreachable.
    """
    # scoped packages (e.g. @angular/core) need the "/" encoded as %2F
    encoded_name = quote(package_name, safe="")
    url = NPM_REGISTRY_URL.format(package=encoded_name)
    try:
        resp = requests.get(url, timeout=timeout)
        if resp.status_code != 200:
            return None
        data = resp.json()
        return data.get("version")
    except (requests.RequestException, ValueError):
        return None


def check_outdated(package_name: str, current_version: str):
    """
    Returns a dict: {latest_version, is_outdated, versions_behind} or None
    if we couldn't determine the latest version / parse either version.

    versions_behind is a rough indicator: how many of (major, minor, patch)
    components differ, weighted toward major being the most significant —
    just returned as the parsed tuples for the caller to interpret/display.
    """
    latest = get_latest_version(package_name)
    if not latest:
        return None

    current_parsed = _parse_version(current_version)
    latest_parsed = _parse_version(latest)
    if not current_parsed or not latest_parsed:
        return None

    is_outdated = current_parsed < latest_parsed

    return {
        "latest_version": latest,
        "is_outdated": is_outdated,
        "current_parsed": current_parsed,
        "latest_parsed": latest_parsed,
    }
