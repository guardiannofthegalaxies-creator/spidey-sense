# Spidey Sense 🕷️

catch what you miss.

Built this to automate the boring-but-critical part of every VAPT/red team engagement — going through every JS file on a target and finding what devs forgot to clean up. Hardcoded keys, outdated packages with public CVEs, weak crypto, exposed source maps... it's all usually just sitting there in plain JS if you bother to look.

Tool has two ways to use it depending on the engagement type:

## 1. Black box (crawl mode)

Just give it a URL, it does the rest. Clicks around the pages, waits for lazy-loaded JS chunks, digs through links, and pulls every single JS file it can find on its own — no manual work needed.

```
python spidey_sense.py https://target.com --depth 2 --max-pages 25
```

## 2. Grey box (auth'd apps)

For apps behind login, didn't want to bake auth handling into the tool itself — too much of a pain to maintain across different auth flows. So instead there's a Tampermonkey userscript (`tampermonkeyscript.txt`) that does the job:

- Load the script into Tampermonkey
- Let it run quietly in the background while you browse the app normally (logged in, doing whatever)
- It captures every JS file loading in the background as you go
- Download the list it collects → feed that txt file into the tool

Same analysis runs either way, tool doesn't care how the URLs got collected.

```
python spidey_sense.py --url-list js_file_list.txt
```

## What the analysis actually checks

- Scans for hardcoded creds/secrets — API keys, tokens (AWS, Slack, GitHub, Discord, JWTs), passwords sitting in plaintext
- Checks all JS dependencies against npm for outdated versions
- Cross-checks those against OSV.dev for known/public CVEs
- Looks at what crypto/hashing is actually being used client-side — flags weak stuff (MD5/SHA1) vs okay stuff (bcrypt/PBKDF2)
- Checks if source maps are exposed (still see this way too often on "secure" apps)

## Setup

```
pip install -r requirements.txt
playwright install chromium
```

Useful flags:
- `--depth` — how many link hops deep to crawl (default 2)
- `--max-pages` — cap on pages visited (default 25)
- `--extra-urls` — manually throw in paths the crawler might not find on its own
- `--json` — dump full report as JSON too
- `--debug` — verbose output when it's misbehaving

## Notes

This is v1, still rough in places, will keep improving it as I use it on more engagements. If you're checking this out, come back later — planning on adding more checks and cleaning up the output as I go.

Only use this on stuff you're actually authorized to test. Obviously.
