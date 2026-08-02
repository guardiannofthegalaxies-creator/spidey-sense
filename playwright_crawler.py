#!/usr/bin/env python3
"""
Playwright-based multi-page crawler.

Same idea as a normal BFS web crawler (visit a page, follow same-origin
links, repeat up to a depth/page limit) — but every page is rendered in a
real headless browser first, so:
  - links that only appear after JS runs are found
  - JS files that get injected dynamically after page load are found
    (not just ones sitting in the raw HTML)

This is intentionally still just the crawling step: it collects pages
visited + every JS file seen. No fingerprinting or vulnerability lookup
yet — that's the next phase.

Usage:
    python playwright_crawler.py https://example.com
    python playwright_crawler.py https://example.com --depth 3 --max-pages 30
"""
import argparse
from urllib.parse import urljoin, urlparse

from playwright.sync_api import sync_playwright


def same_origin(url_a: str, url_b: str) -> bool:
    a, b = urlparse(url_a), urlparse(url_b)
    return (a.scheme, a.netloc) == (b.scheme, b.netloc)


def get_links(page, base_url: str):
    """Return same-origin links found on the *rendered* page."""
    hrefs = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
    links = set()
    for href in hrefs:
        clean = href.split("#")[0]
        if clean and same_origin(base_url, clean):
            links.add(clean)
    return links


RISKY_KEYWORDS = [
    "delete", "submit", "confirm", "pay", "transfer", "logout", "log out",
    "close account", "remove", "cancel subscription", "send money", "withdraw",
]


def is_risky_button(text: str) -> bool:
    lowered = text.lower()
    return any(kw in lowered for kw in RISKY_KEYWORDS)


def click_buttons_and_find_links(page, base_url: str, debug: bool = False, click_wait_ms: int = 1000):
    """
    Clicks non-risky buttons on the current page one at a time, and checks
    for new same-origin links that appear after each click (common on SPAs
    where clicking reveals a hidden div instead of navigating).
    Returns a set of newly discovered links.
    """
    discovered = set()
    before_links = get_links(page, base_url)
    tried_texts = set()
    clicked_count = 0
    skipped_count = 0
    error_count = 0

    SELECTOR = (
        "button, [role=button], [role=tab], a[href='#'], a[href^='javascript:'], "
        "[onclick], input[type=submit], input[type=button]"
    )

    max_rounds = 30  # safety cap so a weird page can't loop forever
    rounds = 0

    while rounds < max_rounds:
        rounds += 1
        buttons = page.query_selector_all(SELECTOR)
        if rounds == 1:
            print(f"    [*] Found {len(buttons)} button-like element(s) on page")

        # find the next button we haven't tried yet, using a FRESH handle
        target = None
        target_text = None
        for b in buttons:
            try:
                t = (b.inner_text() or "").strip() or (b.get_attribute("value") or "").strip()
            except Exception:
                continue
            if t and t not in tried_texts:
                target, target_text = b, t
                break

        if target is None:
            break  # nothing new left to try

        tried_texts.add(target_text)

        if is_risky_button(target_text):
            print(f"    [-] Skipping risky button: '{target_text}'")
            skipped_count += 1
            continue

        try:
            page.wait_for_timeout(300)  # tiny settle pause before each click
            target.click(timeout=3000)
            clicked_count += 1
            page.wait_for_timeout(click_wait_ms)
        except Exception as e:
            print(f"    [!] Click failed on '{target_text}': {type(e).__name__}: {str(e)[:150]}")
            error_count += 1
            continue

        # did clicking actually navigate us to a new page? if so, this is
        # likely an ASP.NET-style full postback, not a meaningless redirect.
        # The response we just landed on may ALREADY contain the revealed
        # content (e.g. the toggled login form + its links) — scan it
        # BEFORE leaving, then go back so we can try remaining buttons
        # with a FRESH element list (old handles are now stale/unusable)
        if page.url.split("#")[0] != base_url.split("#")[0]:
            post_click_links = get_links(page, base_url)
            new_from_postback = post_click_links - before_links - discovered
            if new_from_postback:
                print(f"    [+] Clicking '{target_text}' (via postback) revealed {len(new_from_postback)} new link(s)")
                discovered.update(new_from_postback)
            else:
                print(f"    [i] Clicking '{target_text}' caused a postback but no new links found on the result page")

            try:
                page.goto(base_url, wait_until="domcontentloaded", timeout=15000)
                page.wait_for_timeout(500)
            except Exception:
                break  # can't recover, stop entirely
            continue  # loop back around and re-query fresh buttons

        after_links = get_links(page, base_url)
        new_links = after_links - before_links - discovered
        if new_links:
            print(f"    [+] Clicking '{target_text}' revealed {len(new_links)} new link(s)")
            discovered.update(new_links)

    print(f"    [*] Button pass done: {clicked_count} clicked, {skipped_count} skipped (risky), {error_count} errored")
    return discovered


def crawl(start_url: str, max_depth: int = 2, max_pages: int = 25, wait_ms: int = 2000, debug: bool = False, click_wait_ms: int = 1000, extra_urls=None):
    """
    Returns (visited_pages: set[str], js_files: set[str])

    extra_urls: optional list of known URLs/paths to scan directly, in
    addition to whatever gets discovered via crawling. Useful when you
    already know a page exists (e.g. spotted it in dev tools) but the
    crawler can't reach it via link-following/clicking.
    """
    visited = set()
    js_files = set()
    queue = [(start_url, 0)]

    if extra_urls:
        for u in extra_urls:
            full_url = urljoin(start_url, u)  # handles both full URLs and relative paths like "ForgotPassword.aspx"
            queue.append((full_url, 0))
            print(f"[*] Seeding known URL: {full_url}")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        def handle_request(request):
            if request.resource_type == "script" or request.url.split("?")[0].endswith(".js"):
                js_files.add(request.url)

        page.on("request", handle_request)

        while queue and len(visited) < max_pages:
            url, depth = queue.pop(0)
            if url in visited or depth > max_depth:
                continue

            print(f"[*] ({depth}) Visiting: {url}")
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=30000)
            except Exception as e:
                print(f"    [!] Failed to load: {e}")
                continue

            page.wait_for_timeout(wait_ms)  # let late/lazy scripts fire
            try:
                page.wait_for_load_state("load", timeout=10000)
            except Exception:
                pass  # some sites never fully settle; proceed anyway
            visited.add(url)
            print(f"    [+] Loaded successfully ({len(visited)}/{max_pages} pages so far)")

            if depth < max_depth:
                if debug:
                    all_hrefs = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
                    print(f"    [debug] Raw <a href> tags found on page ({len(all_hrefs)}):")
                    for h in all_hrefs:
                        print(f"        {h}")
                    button_texts = page.eval_on_selector_all(
                        "button, [role=button], [role=tab], a[href='#'], a[href^='javascript:'], [onclick]",
                        "els => els.map(e => e.innerText.trim()).filter(t => t)"
                    )
                    if button_texts:
                        print(f"    [debug] Clickable-looking elements found (not yet followed): {button_texts}")

                new_links = 0
                for link in get_links(page, start_url):
                    if link not in visited and len(visited) + len(queue) < max_pages:
                        queue.append((link, depth + 1))
                        new_links += 1

                print(f"    [*] Trying buttons to reveal any hidden links...")
                revealed = click_buttons_and_find_links(page, url, debug=debug, click_wait_ms=click_wait_ms)
                for link in revealed:
                    if link not in visited and len(visited) + len(queue) < max_pages:
                        queue.append((link, depth + 1))
                        new_links += 1

                print(f"    [+] Found {new_links} new same-origin link(s) to follow (including button-revealed)")

        browser.close()

    return visited, js_files


def main():
    parser = argparse.ArgumentParser(description="Playwright-based multi-page crawler")
    parser.add_argument("url", help="Starting URL")
    parser.add_argument("--depth", type=int, default=2, help="Max crawl depth (default: 2)")
    parser.add_argument("--max-pages", type=int, default=25, help="Max pages to visit (default: 25)")
    parser.add_argument("--wait", type=int, default=2000, help="Extra wait per page in ms (default: 2000)")
    parser.add_argument("--debug", action="store_true", help="Print every link/button found on each page, not just ones followed")
    parser.add_argument("--click-wait", type=int, default=1000, help="Time to wait after each button click in ms (default: 1000, increase for slow-rendering sites)")
    parser.add_argument("--extra-urls", nargs="+", default=None, help="Known URLs/paths to scan directly (e.g. --extra-urls ForgotPassword.aspx NewUserRegistration.aspx)")
    args = parser.parse_args()

    print(f"[*] Starting crawl at {args.url} (depth={args.depth}, max_pages={args.max_pages})\n")
    pages, js_files = crawl(args.url, max_depth=args.depth, max_pages=args.max_pages, wait_ms=args.wait, debug=args.debug, click_wait_ms=args.click_wait, extra_urls=args.extra_urls)

    print(f"\n[+] Crawled {len(pages)} page(s):")
    for i, p in enumerate(sorted(pages), 1):
        print(f"    {i}. {p}")

    print(f"\n[+] Found {len(js_files)} JS file(s)")
    for j in sorted(js_files):
        print(f"    - {j}")


if __name__ == "__main__":
    main()
