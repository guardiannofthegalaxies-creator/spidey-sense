"""
Given a JS file's URL and content, identify the library name and version
using the signature database (content patterns take priority, filename is
the fallback), then fall back further to a generic filename heuristic.
"""
import re
from urllib.parse import urlparse

from signatures import LIBRARIES, GENERIC_FILENAME_PATTERN


def _filename_from_url(url: str) -> str:
    return urlparse(url).path.rsplit("/", 1)[-1]


def identify(url: str, content: str):
    """
    Returns (library_name, version) or None if no match found.
    """
    filename = _filename_from_url(url)

    for lib in LIBRARIES:
        # Try content patterns first (more reliable than filenames)
        for pattern in lib["content_patterns"]:
            match = re.search(pattern, content[:5000])  # header/banner region
            if match and match.groups():
                return lib["name"], match.group(1)

        # Fall back to filename pattern for this specific library
        if lib["filename_pattern"]:
            match = re.search(lib["filename_pattern"], filename, re.IGNORECASE)
            if match and match.groups() and match.group(1):
                return lib["name"], match.group(1)

    # Generic fallback: "somelib-1.2.3.min.js"
    match = GENERIC_FILENAME_PATTERN.search(filename)
    if match:
        return match.group(1).lower(), match.group(2)

    return None
