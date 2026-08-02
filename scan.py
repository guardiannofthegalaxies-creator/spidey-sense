#!/usr/bin/env python3
"""
One-click JS vulnerability scanner — styled edition.

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
    python scan.py https://example.com
    python scan.py https://example.com --depth 2 --max-pages 20
    python scan.py --url-list js_file_list.txt
    python scan.py https://example.com --json report.json
"""
import argparse
import json
import sys

import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.text import Text
from rich import box

from playwright_crawler import crawl
from fingerprint import identify
from osv_check import check_package
from npm_check import check_outdated
from secret_scanner import scan_js_file, has_findings
from crypto_analysis import analyze_all

console = Console()
USER_AGENT = "onclick_scan/1.0 (+authorized-security-audit-tool)"

BANNER = r"""
[bold cyan]     _ _____   __      __     _  _____                 [/]
[bold cyan]  _ | / ____|  \ \    / /    | |/ ____|                [/]
[bold cyan] | || \ (___     \ \  / /_   _| | (___   ___ __ _ _ __  [/]
[bold cyan] |__   _\___ \     \ \/ / | | | |\___ \ / __/ _` | '_ \ [/]
[bold cyan]    | |____) |      \  /| |_| | |____) | (_| (_| | | | |[/]
[bold cyan]    |_|_____/        \/  \__,_|_|_____/ \___\__,_|_| |_|[/]
[dim]           crawl -> fingerprint -> vulnerable + outdated check[/]
"""


def fetch_js_contents(js_urls):
    session = requests.Session()
    contents = {}
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Downloading JS files...", total=len(js_urls))
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
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        console=console,
    ) as progress:
        task = progress.add_task("[magenta]Fingerprinting libraries...", total=len(contents))
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
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        console=console,
    ) as progress:
        task = progress.add_task("[yellow]Checking OSV + npm registry...", total=len(detected))
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
        return Text("? UNKNOWN", style="bold yellow")
    if vulns:
        return Text(f"X VULNERABLE ({len(vulns)} CVE)", style="bold red")
    if outdated and outdated["is_outdated"]:
        return Text("! OUTDATED", style="bold yellow")
    return Text("OK CLEAN", style="bold green")


def print_report_table(report):
    table = Table(box=box.ROUNDED, show_lines=False, header_style="bold white on dark_blue")
    table.add_column("Library", style="cyan", no_wrap=True)
    table.add_column("Version")
    table.add_column("Latest")
    table.add_column("Status")
    table.add_column("Files", justify="right")

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
                f"[bold red]{v['id']}[/] (severity: {v['severity']}) - {v['summary'][:100]}\n  [dim]{v['link']}[/]"
                for v in vulns
            )
            console.print(Panel(lines, title=f"[red]{entry['library']} {entry['version']} - CVE detail[/]", border_style="red"))


def print_summary(pages_count, js_count, report, unidentified):
    vulnerable = sum(1 for e in report if e["vulnerabilities"])
    outdated = sum(1 for e in report if e["outdated"] and e["outdated"]["is_outdated"])
    unknown = sum(1 for e in report if e["vulnerabilities"] is None)

    body = (
        f"[bold]{len(report)}[/] libraries identified"
        + (f"  |  [dim]{pages_count} pages crawled, {js_count} JS files found[/]" if pages_count is not None else "")
        + f"\n[bold red]{vulnerable}[/] with known CVEs   "
        f"[bold yellow]{outdated}[/] outdated   "
        f"[bold yellow]{unknown}[/] could not be checked   "
        f"[dim]{len(unidentified)} unidentified file(s)[/]"
    )
    style = "red" if vulnerable else ("yellow" if outdated or unknown else "green")
    console.print(Panel(body, title="SUMMARY", border_style=style, box=box.DOUBLE))


def scan_all_secrets(contents):
    """Runs the full secrets/crypto/endpoint/juice scan across every JS file."""
    session = requests.Session()
    findings = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        console=console,
    ) as progress:
        task = progress.add_task("[bold red]Scanning for secrets & juice...", total=len(contents))
        for url, content in contents.items():
            result = scan_js_file(url, content, session=session)
            if has_findings(result):
                findings.append(result)
            progress.advance(task)
    return findings


def print_secrets_report(findings):
    if not findings:
        console.print("[green]No secrets, weak crypto, or other sensitive data found.[/]")
        return

    for result in findings:
        console.rule(f"[bold white on red] {result['url']} [/]", style="red")

        if result["secrets"]:
            for s in result["secrets"]:
                console.print(f"  [bold red]SECRET[/] [{s['type']}] {s['match']}")

        if result["weak_crypto"]:
            for w in result["weak_crypto"]:
                console.print(f"  [bold yellow]WEAK CRYPTO[/] [{w['type']}] ...{w['context']}...")

        if result["hardcoded_crypto_keys"]:
            for k in result["hardcoded_crypto_keys"]:
                console.print(f"  [bold red]HARDCODED KEY[/] near crypto call: {k['match']}")

        if result["risky_comments"]:
            for c in result["risky_comments"][:5]:
                console.print(f"  [yellow]RISKY COMMENT[/] {c}")

        internal_eps = [e for e in result["endpoints"] if e["flagged_internal"]]
        for e in internal_eps[:10]:
            console.print(f"  [cyan]INTERNAL-LOOKING ENDPOINT[/] {e['url']}")

        for b in result["cloud_storage"]:
            console.print(f"  [magenta]CLOUD STORAGE REF[/] {b}")

        for a in result["api_schema_endpoints"]:
            console.print(f"  [magenta]API SCHEMA/DOCS ENDPOINT[/] {a}")

        for w in result["websocket_urls"]:
            console.print(f"  [blue]WEBSOCKET URL[/] {w}")

        if result["sentry_dsn"]:
            console.print(f"  [yellow]SENTRY DSN[/] {result['sentry_dsn']}")

        for a in result["analytics_ids"]:
            console.print(f"  [dim]ANALYTICS ID[/] [{a['type']}] {a['value']}")

        if result["emails"]:
            console.print(f"  [dim]EMAILS FOUND[/] {', '.join(result['emails'][:5])}"
                          + (f" (+{len(result['emails'])-5} more)" if len(result['emails']) > 5 else ""))

        if result["feature_flags"]:
            console.print(f"  [cyan]FEATURE FLAG STRINGS[/] {', '.join(result['feature_flags'])}")

        if result["source_map"] and result["source_map"]["accessible"]:
            console.print(f"  [bold red]EXPOSED SOURCE MAP[/] {result['source_map']['map_url']}")

        console.print()


def scan_all_crypto(contents):
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        console=console,
    ) as progress:
        task = progress.add_task("[bold blue]Analyzing encryption usage...", total=len(contents))
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
        console.print("[dim]No encryption/hashing usage detected in any JS file.[/]")
        return

    for entry in crypto_findings:
        console.rule(f"[bold white on blue] {entry['url']} [/]", style="blue")

        if entry["libraries"]:
            console.print(f"  [bold]Library/API detected:[/] {', '.join(entry['libraries'])}")

        table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
        table.add_column("Algorithm")
        table.add_column("Mode")
        table.add_column("Assessment")
        table.add_column("Count", justify="right")

        for algo in entry["algorithms"]:
            modes_seen = ", ".join(sorted(set(o["mode"] for o in algo["occurrences"] if o["mode"]))) or "-"
            is_weak = "weak" in algo["classification"] or "broken" in algo["classification"] or "not encryption" in algo["classification"]
            style = "bold red" if is_weak else "bold green"
            table.add_row(
                Text(algo["algorithm"], style=style),
                modes_seen,
                algo["classification"],
                str(algo["total_occurrences"]),
            )

        console.print(table)

        # show actual code logic for each occurrence, so it can be reviewed directly
        for algo in entry["algorithms"]:
            for i, occ in enumerate(algo["occurrences"], 1):
                mode_label = f" ({occ['mode']} mode)" if occ["mode"] else ""
                console.print(Panel(
                    occ["context"],
                    title=f"[dim]{algo['algorithm']}{mode_label} \u2014 occurrence {i}/{algo['total_occurrences']}[/]",
                    border_style="dim",
                ))
        console.print()


def run_analysis(js_urls, pages_count=None, json_path=None, target_label=""):
    if not js_urls:
        console.print("[yellow]No JS files to analyze.[/]")
        return

    console.print()
    contents = fetch_js_contents(js_urls)

    console.print()
    detected, unidentified = fingerprint_all(contents)

    report = []
    if detected:
        console.print()
        report = check_all(detected)

        console.print()
        console.rule("[bold]Results \u2014 Vulnerable / Outdated Libraries[/]")
        print_report_table(report)
        console.print()
        print_summary(pages_count, len(js_urls), report, unidentified)
    else:
        console.print("[yellow]Could not identify any known libraries.[/]")

    # Secrets scanning runs on ALL downloaded JS regardless of whether we
    # recognized it as a known library — custom app code is often exactly
    # where hardcoded secrets live, so it must not be skipped here.
    console.print()
    console.rule("[bold red]Results \u2014 Secrets & Sensitive Data[/]")
    secret_findings = scan_all_secrets(contents)
    console.print()
    print_secrets_report(secret_findings)

    console.print()
    console.rule("[bold blue]Results \u2014 Encryption Usage[/]")
    crypto_findings = scan_all_crypto(contents)
    console.print()
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
        console.print(f"\n[green]Full report written to[/] {json_path}")


def main():
    parser = argparse.ArgumentParser(description="One-click crawl + vulnerable/outdated JS library scanner")
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
        console.print("[bold red]Error:[/] provide either a URL to crawl, or --url-list <file.txt>")
        sys.exit(1)

    if args.url_list:
        console.rule(f"[bold]List mode - {args.url_list}[/]")
        with open(args.url_list) as f:
            js_urls = [line.strip() for line in f if line.strip()]
        console.print(f"[green]Loaded {len(js_urls)} URL(s) from file[/]\n")
        run_analysis(js_urls, pages_count=None, json_path=args.json, target_label=args.url_list)
    else:
        console.rule(f"[bold]Crawl mode - {args.url}[/]")
        pages, js_urls = crawl(
            args.url,
            max_depth=args.depth,
            max_pages=args.max_pages,
            wait_ms=args.wait,
            debug=args.debug,
            click_wait_ms=args.click_wait,
            extra_urls=args.extra_urls,
        )
        console.print(f"\n[green]Crawled {len(pages)} page(s), found {len(js_urls)} JS file(s)[/]")
        run_analysis(js_urls, pages_count=len(pages), json_path=args.json, target_label=args.url)


if __name__ == "__main__":
    main()
