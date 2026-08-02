#!/usr/bin/env python3
"""
Spidey Sense — one-click JS vulnerability scanner.
Built by Hitarth.

Two modes:
  1. CRAWL MODE (give it a URL): crawls the site with Playwright, finds
     every JS file, fingerprints + checks each one.
  2. LIST MODE (give it --url-list file.txt): skips crawling entirely and
     scans a pre-existing list of JS URLs — built for pairing with the
     js_harvester.user.js Tampermonkey script, since URLs gathered from an
     authenticated browsing session can't be reached by crawling alone.

IMPORTANT: Only run against sites you own or are explicitly authorized to
test.

Usage:
    python spidey_sense.py https://example.com
    python spidey_sense.py https://example.com --depth 2 --max-pages 20
    python spidey_sense.py --url-list js_file_list.txt
    python spidey_sense.py https://example.com --json report.json
"""
import argparse
import json
import sys

import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.spinner import SPINNERS
from rich.text import Text
from rich.theme import Theme
from rich.align import Align
from rich import box

from playwright_crawler import crawl
from fingerprint import identify
from osv_check import check_package
from npm_check import check_outdated
from secret_scanner import scan_js_file, has_findings
from crypto_analysis import analyze_all

# --------------------------------------------------------------------------
# Theme — strictly red / blue / white, nothing else
# --------------------------------------------------------------------------
THEME = Theme({
    "bad": "bold red",
    "warn": "bold white",
    "good": "bold blue",
    "info": "dim white",
    "accent": "bold red",
    "accent2": "bold blue",
    "hairline": "dim white",
})
console = Console(theme=THEME)
USER_AGENT = "spidey_sense/2.0 (+authorized-security-audit-tool)"

# a little spider crawling across the progress bars instead of plain dots
SPINNERS["spidey"] = {"interval": 120, "frames": ["🕷️ ", " 🕷️", "🕸️ ", " 🕸️"]}

BANNER = r"""[bold red]   ____     _    __           ____                [/bold red]
[bold white]  / __/__  (_)__/ /__ __ __  / __/__ ___  ___ ___ [/bold white]
[bold white] _\ \/ _ \/ / _  / -_) // / _\ \/ -_) _ \(_-</ -_)[/bold white]
[bold blue]/___/ .__/_/\_,_/\__/\_, / /___/\__/_//_/___/\__/ [/bold blue]
[bold blue]   /_/              /___/                         [/bold blue]

[dim italic]                                       — Hitarth 🕷️[/dim italic]
"""


# --------------------------------------------------------------------------
# small display helpers — left-aligned, not full-width, easy on the eyes
# --------------------------------------------------------------------------
def section(title, color="accent"):
    """A short, left-aligned section marker instead of a full-width rule."""
    console.print()
    console.print(f"[{color}]🕸  {title}[/{color}]")
    console.print(f"[hairline]{'─' * min(len(title) + 4, 46)}[/hairline]")


def sub(text, marker="·", color="info"):
    """A quiet one-line note, indented, left-aligned."""
    console.print(f"   [{color}]{marker}[/{color}] {text}")


def make_progress(label, style="red"):
    spinner_style = "bold red" if style == "red" else "bold blue"
    bar_complete = "red" if style == "red" else "blue"
    return Progress(
        SpinnerColumn(spinner_name="spidey", style=spinner_style),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(complete_style=bar_complete, finished_style="bold white", style="grey23"),
        TextColumn("[dim]{task.completed}/{task.total}[/dim]"),
        console=console,
    )


def fetch_js_contents(js_urls):
    session = requests.Session()
    contents = {}
    with make_progress("Downloading", style="blue") as progress:
        task = progress.add_task("[white]spinning up connections...[/]", total=len(js_urls))
        for url in js_urls:
            try:
                resp = session.get(url, timeout=10, headers={"User-Agent": USER_AGENT})
                if resp.status_code == 200:
                    contents[url] = resp.text
            except requests.RequestException:
                pass
            progress.advance(task)
    return contents


def fingerprint_all(contents):
    detected = {}
    unidentified = []
    with make_progress("Fingerprinting", style="red") as progress:
        task = progress.add_task("[white]tracing library signatures...[/]", total=len(contents))
        for url, content in contents.items():
            result = identify(url, content)
            if result:
                detected.setdefault(result, []).append(url)
            else:
                unidentified.append(url)
            progress.advance(task)
    return detected, unidentified


def check_all(detected):
    report = []
    with make_progress("Checking", style="blue") as progress:
        task = progress.add_task("[white]checking OSV + npm registry...[/]", total=len(detected))
        for (name, version), lib_urls in sorted(detected.items()):
            vulns = check_package(name, version)
            outdated_info = check_outdated(name, version)
            report.append({
                "library": name,
                "version": version,
                "files": lib_urls,
                "vulnerabilities": vulns,
                "outdated": outdated_info,
            })
            progress.advance(task)
    return report


def status_cell(entry):
    vulns = entry["vulnerabilities"]
    outdated = entry["outdated"]

    if vulns is None:
        return Text("?  UNKNOWN", style="warn")
    if vulns:
        return Text(f"✕  VULNERABLE ({len(vulns)} CVE)", style="bad")
    if outdated and outdated["is_outdated"]:
        return Text("!  OUTDATED", style="warn")
    return Text("✓  CLEAN", style="good")


def print_report_table(report):
    table = Table(
        box=box.SIMPLE_HEAVY,
        show_lines=False,
        header_style="bold white on red",
        border_style="blue",
        pad_edge=False,
    )
    table.add_column("Library", style="bold white", no_wrap=True)
    table.add_column("Version", style="dim white")
    table.add_column("Latest", style="dim white")
    table.add_column("Status")
    table.add_column("Files", justify="right", style="dim white")

    for entry in report:
        latest = entry["outdated"]["latest_version"] if entry["outdated"] else "?"
        table.add_row(
            entry["library"],
            entry["version"],
            latest,
            status_cell(entry),
            str(len(entry["files"])),
        )

    console.print(table)

    # detail panels for anything with real findings
    for entry in report:
        vulns = entry["vulnerabilities"]
        if vulns:
            lines = "\n".join(
                f"[bad]{v['id']}[/bad] [dim](severity: {v['severity']})[/dim] — {v['summary'][:100]}\n  [dim]{v['link']}[/dim]"
                for v in vulns
            )
            console.print(Panel(
                lines,
                title=f"[bad]🕷  {entry['library']} {entry['version']} — CVE detail[/bad]",
                border_style="red",
                box=box.ROUNDED,
            ))


def print_summary(pages_count, js_count, report, unidentified):
    vulnerable = sum(1 for e in report if e["vulnerabilities"])
    outdated = sum(1 for e in report if e["outdated"] and e["outdated"]["is_outdated"])
    unknown = sum(1 for e in report if e["vulnerabilities"] is None)

    body = (
        f"[bold white]{len(report)}[/bold white] libraries identified"
        + (f"   [dim]{pages_count} pages crawled, {js_count} JS files found[/dim]" if pages_count is not None else "")
        + f"\n[bad]{vulnerable} with known CVEs[/bad]   "
        f"[warn]{outdated} outdated[/warn]   "
        f"[warn]{unknown} unchecked[/warn]   "
        f"[dim]{len(unidentified)} unidentified file(s)[/dim]"
    )
    style = "red" if vulnerable else ("white" if outdated or unknown else "blue")
    console.print(Panel(body, title="🕸  SUMMARY  🕸", border_style=style, box=box.DOUBLE))


def scan_all_secrets(contents):
    """Runs the full secrets/crypto/endpoint/juice scan across every JS file."""
    session = requests.Session()
    findings = []
    with make_progress("Secrets", style="red") as progress:
        task = progress.add_task("[white]hunting for secrets & juice...[/]", total=len(contents))
        for url, content in contents.items():
            result = scan_js_file(url, content, session=session)
            if has_findings(result):
                findings.append(result)
            progress.advance(task)
    return findings


def print_secrets_report(findings):
    if not findings:
        console.print("[good]🕷  Nothing caught in the web — no secrets, weak crypto, or sensitive data found.[/good]")
        return

    for result in findings:
        section(result["url"], color="accent")

        if result["secrets"]:
            for s in result["secrets"]:
                sub(f"[bad]SECRET[/bad]  \\[{s['type']}] {s['match']}", marker="🕷")

        if result["weak_crypto"]:
            for w in result["weak_crypto"]:
                sub(f"[warn]WEAK CRYPTO[/warn]  \\[{w['type']}] ...{w['context']}...", marker="!")

        if result["hardcoded_crypto_keys"]:
            for k in result["hardcoded_crypto_keys"]:
                sub(f"[bad]HARDCODED KEY[/bad]  near crypto call: {k['match']}", marker="🕷")

        if result["risky_comments"]:
            for c in result["risky_comments"][:5]:
                sub(f"[warn]RISKY COMMENT[/warn]  {c}", marker="!")

        internal_eps = [e for e in result["endpoints"] if e["flagged_internal"]]
        for e in internal_eps[:10]:
            sub(f"[good]INTERNAL ENDPOINT[/good]  {e['url']}", marker="·")

        for b in result["cloud_storage"]:
            sub(f"[good]CLOUD STORAGE REF[/good]  {b}", marker="·")

        for a in result["api_schema_endpoints"]:
            sub(f"[good]API SCHEMA/DOCS[/good]  {a}", marker="·")

        for w in result["websocket_urls"]:
            sub(f"[good]WEBSOCKET URL[/good]  {w}", marker="·")

        if result["sentry_dsn"]:
            sub(f"[warn]SENTRY DSN[/warn]  {result['sentry_dsn']}", marker="!")

        for a in result["analytics_ids"]:
            sub(f"[dim]ANALYTICS ID[/dim]  \\[{a['type']}] {a['value']}", marker="·")

        if result["emails"]:
            extra = f" (+{len(result['emails'])-5} more)" if len(result["emails"]) > 5 else ""
            sub(f"[dim]EMAILS FOUND[/dim]  {', '.join(result['emails'][:5])}{extra}", marker="·")

        if result["feature_flags"]:
            sub(f"[good]FEATURE FLAGS[/good]  {', '.join(result['feature_flags'])}", marker="·")

        if result["source_map"] and result["source_map"]["accessible"]:
            sub(f"[bad]EXPOSED SOURCE MAP[/bad]  {result['source_map']['map_url']}", marker="🕷")

        console.print()


def scan_all_crypto(contents):
    with make_progress("Crypto", style="blue") as progress:
        task = progress.add_task("[white]inspecting encryption usage...[/]", total=len(contents))
        results = []
        for url, content in contents.items():
            from crypto_analysis import analyze_crypto_usage
            r = analyze_crypto_usage(url, content)
            if r:
                results.append(r)
            progress.advance(task)
    return results


def print_crypto_report(crypto_findings):
    if not crypto_findings:
        console.print("[info]🕸  No encryption/hashing usage detected in any JS file.[/info]")
        return

    for entry in crypto_findings:
        section(entry["url"], color="accent2")

        if entry["libraries"]:
            sub(f"[bold white]Library/API detected:[/bold white] {', '.join(entry['libraries'])}", marker="·")

        table = Table(
            box=box.SIMPLE_HEAVY,
            show_header=True,
            header_style="bold white on blue",
            border_style="blue",
            pad_edge=False,
        )
        table.add_column("Algorithm")
        table.add_column("Mode", style="dim white")
        table.add_column("Assessment")
        table.add_column("Count", justify="right", style="dim white")

        for algo in entry["algorithms"]:
            modes_seen = ", ".join(sorted(set(o["mode"] for o in algo["occurrences"] if o["mode"]))) or "-"
            is_weak = "weak" in algo["classification"] or "broken" in algo["classification"] or "not encryption" in algo["classification"]
            style = "bad" if is_weak else "good"
            table.add_row(
                Text(algo["algorithm"], style=style),
                modes_seen,
                Text(algo["classification"], style="dim white"),
                str(algo["total_occurrences"]),
            )

        console.print(table)

        # show actual code logic for each occurrence, so it can be reviewed directly
        for algo in entry["algorithms"]:
            for i, occ in enumerate(algo["occurrences"], 1):
                mode_label = f" ({occ['mode']} mode)" if occ["mode"] else ""
                console.print(Panel(
                    occ["context"],
                    title=f"[dim]{algo['algorithm']}{mode_label} — occurrence {i}/{algo['total_occurrences']}[/dim]",
                    border_style="dim white",
                    box=box.MINIMAL,
                ))
        console.print()


def run_analysis(js_urls, pages_count=None, json_path=None, target_label=""):
    if not js_urls:
        console.print("[warn]No JS files to analyze.[/warn]")
        return

    contents = fetch_js_contents(js_urls)
    detected, unidentified = fingerprint_all(contents)

    report = []
    if detected:
        report = check_all(detected)
        section("Vulnerable / Outdated Libraries", color="accent")
        print_report_table(report)
        console.print()
        print_summary(pages_count, len(js_urls), report, unidentified)
    else:
        console.print("[warn]Could not identify any known libraries.[/warn]")

    # Secrets scanning runs on ALL downloaded JS regardless of whether we
    # recognized it as a known library — custom app code is often exactly
    # where hardcoded secrets live, so it must not be skipped here.
    section("Secrets & Sensitive Data", color="accent")
    secret_findings = scan_all_secrets(contents)
    print_secrets_report(secret_findings)

    section("Encryption Usage", color="accent2")
    crypto_findings = scan_all_crypto(contents)
    print_crypto_report(crypto_findings)

    if json_path:
        with open(json_path, "w") as f:
            json.dump({
                "target": target_label,
                "pages_crawled": pages_count,
                "libraries": report,
                "unidentified_files": unidentified,
                "secret_findings": secret_findings,
                "crypto_findings": crypto_findings,
            }, f, indent=2)
        sub(f"[good]Full report written to[/good] {json_path}", marker="✓")


def main():
    parser = argparse.ArgumentParser(description="Spidey Sense — crawl + vulnerable/outdated JS library scanner")
    parser.add_argument("url", nargs="?", help="Starting URL (crawl mode)")
    parser.add_argument("--url-list", metavar="FILE", help="Path to a text file of JS URLs (list mode, e.g. from js_harvester.user.js) - skips crawling entirely")
    parser.add_argument("--depth", type=int, default=2)
    parser.add_argument("--max-pages", type=int, default=25)
    parser.add_argument("--wait", type=int, default=2000)
    parser.add_argument("--click-wait", type=int, default=1000)
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--extra-urls", nargs="+", default=None)
    parser.add_argument("--json", metavar="FILE", help="Also write full report as JSON to FILE")
    args = parser.parse_args()

    console.print(BANNER)

    if not args.url and not args.url_list:
        console.print("[bad]Error:[/bad] provide either a URL to crawl, or --url-list <file.txt>")
        sys.exit(1)

    if args.url_list:
        section(f"List mode — {args.url_list}", color="accent")
        with open(args.url_list) as f:
            js_urls = [line.strip() for line in f if line.strip()]
        sub(f"[good]Loaded {len(js_urls)} URL(s) from file[/good]", marker="✓")
        run_analysis(js_urls, pages_count=None, json_path=args.json, target_label=args.url_list)
    else:
        section(f"Crawl mode — {args.url}", color="accent2")
        pages, js_urls = crawl(
            args.url,
            max_depth=args.depth,
            max_pages=args.max_pages,
            wait_ms=args.wait,
            debug=args.debug,
            click_wait_ms=args.click_wait,
            extra_urls=args.extra_urls,
        )
        sub(f"[good]Crawled {len(pages)} page(s), found {len(js_urls)} JS file(s)[/good]", marker="✓")
        run_analysis(js_urls, pages_count=len(pages), json_path=args.json, target_label=args.url)


if __name__ == "__main__":
    main()
