"""
Signature database for fingerprinting common JS libraries and their versions
from crawled JavaScript file content and filenames.

Each entry has:
  - name: canonical package name (used for OSV / npm ecosystem lookups)
  - content_patterns: list of regexes run against file content; first capture
    group must be the version string.
  - filename_pattern: regex run against the URL/filename; first capture group
    is the version string.
"""
import re

LIBRARIES = [
    {
        "name": "jquery",
        "content_patterns": [
            r"jQuery\s+JavaScript\s+Library\s+v(\d+\.\d+\.\d+)",
            r"jQuery\s+v(\d+\.\d+\.\d+)",
        ],
        "filename_pattern": r"jquery[.\-]?(\d+\.\d+\.\d+)(?:\.min)?\.js",
    },
    {
        "name": "angular",
        "content_patterns": [
            r"angular\.js@?\s*v?(\d+\.\d+\.\d+)",
            r"AngularJS\s+v(\d+\.\d+\.\d+)",
        ],
        "filename_pattern": r"angular[.\-]?(\d+\.\d+\.\d+)(?:\.min)?\.js",
    },
    {
        "name": "@angular/core",
        "content_patterns": [
            r"Angular\s+(\d+\.\d+\.\d+)",
        ],
        "filename_pattern": None,
    },
    {
        "name": "lodash",
        "content_patterns": [
            r"Lodash\s+v?(\d+\.\d+\.\d+)",
            r"lodash\.js\s+v(\d+\.\d+\.\d+)",
            r"VERSION\s*=\s*['\"](\d+\.\d+\.\d+)['\"]",
        ],
        "filename_pattern": r"lodash[.\-]?(\d+\.\d+\.\d+)?(?:\.min)?\.js",
    },
    {
        "name": "moment",
        "content_patterns": [
            r"moment\.js\s*\n?\s*//!\s*version\s*:\s*(\d+\.\d+\.\d+)",
            r"//!\s*version\s*:\s*(\d+\.\d+\.\d+)",
            r"moment\.version\s*=\s*['\"](\d+\.\d+\.\d+)['\"]",
        ],
        "filename_pattern": r"moment[.\-]?(\d+\.\d+\.\d+)?(?:\.min)?\.js",
    },
    {
        "name": "bootstrap",
        "content_patterns": [
            r"Bootstrap\s+v(\d+\.\d+\.\d+)",
        ],
        "filename_pattern": r"bootstrap[.\-]?(\d+\.\d+\.\d+)(?:\.min)?\.js",
    },
    {
        "name": "vue",
        "content_patterns": [
            r"Vue\.js\s+v(\d+\.\d+\.\d+)",
        ],
        "filename_pattern": r"vue[.\-]?(\d+\.\d+\.\d+)?(?:\.min)?\.js",
    },
    {
        "name": "react",
        "content_patterns": [
            r"React\s+v(\d+\.\d+\.\d+)",
        ],
        "filename_pattern": r"react[.\-]?(\d+\.\d+\.\d+)?(?:\.min|\.production\.min|\.development)?\.js",
    },
    {
        "name": "handlebars",
        "content_patterns": [
            r"Handlebars\s+v(\d+\.\d+\.\d+)",
        ],
        "filename_pattern": r"handlebars[.\-]?(\d+\.\d+\.\d+)?(?:\.min)?\.js",
    },
    {
        "name": "underscore",
        "content_patterns": [
            r"Underscore\.js\s+(\d+\.\d+\.\d+)",
        ],
        "filename_pattern": r"underscore[.\-]?(\d+\.\d+\.\d+)?(?:\.min)?\.js",
    },
    {
        "name": "backbone",
        "content_patterns": [
            r"Backbone\.js\s+(\d+\.\d+\.\d+)",
        ],
        "filename_pattern": r"backbone[.\-]?(\d+\.\d+\.\d+)?(?:\.min)?\.js",
    },
    {
        "name": "d3",
        "content_patterns": [
            r"d3\s+v(\d+\.\d+\.\d+)",
        ],
        "filename_pattern": r"d3[.\-]?v?(\d+\.\d+\.\d+)?(?:\.min)?\.js",
    },
    {
        "name": "swiper",
        "content_patterns": [
            r"Swiper\s+(\d+\.\d+\.\d+)",
        ],
        "filename_pattern": r"swiper[.\-]?(\d+\.\d+\.\d+)?(?:\.min)?\.js",
    },
    {
        "name": "axios",
        "content_patterns": [
            r"axios\s+v(\d+\.\d+\.\d+)",
        ],
        "filename_pattern": r"axios[.\-]?(\d+\.\d+\.\d+)?(?:\.min)?\.js",
    },
    {
        "name": "chart.js",
        "content_patterns": [
            r"Chart\.js\s+v(\d+\.\d+\.\d+)",
        ],
        "filename_pattern": r"chart[.\-]?(\d+\.\d+\.\d+)?(?:\.min)?\.js",
    },
]

# Generic fallback: filename patterns like "libname-1.2.3.min.js" or
# "libname.1.2.3.js" for libraries not explicitly listed above.
GENERIC_FILENAME_PATTERN = re.compile(
    r"([a-zA-Z][a-zA-Z0-9._-]*?)[-.](\d+\.\d+\.\d+)(?:\.min)?\.js$"
)
