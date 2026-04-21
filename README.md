# Bscan

A wpscan-style fingerprinter and vulnerability matcher for **1C-Bitrix** sites.
Identifies Bitrix presence, core version, installed modules / templates / components,
and correlates detected versions against a local YAML vulnerability database.

```
 ____
| __ )  ___  ___ __ _ _ __
|  _ \ / __|/ __/ _` | '_ \
| |_) |\__ \ (_| (_| | | | |
|____/ |___/\___\__,_|_| |_|

  1C-Bitrix plugin & version scanner
```

> **Authorized testing only.** Run Bscan only against systems you own or have
> explicit written permission to test. You are responsible for your own use.

---

## Features

- **Fingerprinting** — detects Bitrix via cookies (`BITRIX_SM_*`), headers
  (`X-Powered-CMS`), `<meta generator>`, `/bitrix/admin`, `/bitrix/js/main/core/core.js`,
  and `robots.txt`. Emits a confidence score and list of matched signals.
- **Core version** — extracted from `generator` meta and `core.js`.
- **Module scanning** — parallel probes of common Bitrix modules via
  `/bitrix/modules/<name>/install/version.php`; also mines `?v=` query strings,
  templates (`/bitrix/templates/…`), and components (`/bitrix/components/…`)
  out of the root HTML.
- **Vulnerability matching** — YAML database (`data/vulns.yaml`) with
  `affected` range / `fixed_in` logic.
- **Output** — Rich-formatted terminal tables **or** machine-readable JSON.
- **Progress bar** — live fingerprint + module-probe progress in the TTY;
  auto-suppressed for non-TTY / `--json` / `--quiet`.
- **Proxy-friendly** — route through Burp or any HTTP(S) proxy with `--proxy`.

---

## Install

Requires Python 3.10+.

```bash
cd ~/Program/Bscan
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Dependencies: `httpx[http2]`, `pyyaml`, `rich`.

---

## Usage

```bash
# Single target
.venv/bin/python bscan.py -u https://target.tld

# Through Burp, ignoring TLS
.venv/bin/python bscan.py -u https://target.tld \
    --proxy http://127.0.0.1:8080 --insecure

# JSON output (clean stdout, no banner, no progress)
.venv/bin/python bscan.py -u https://target.tld --json > report.json

# Batch from a file (one URL per line, # comments allowed)
.venv/bin/python bscan.py -f targets.txt

# Skip module scan (faster; fingerprint only)
.venv/bin/python bscan.py -u https://target.tld --no-modules
```

### Flags

| Flag | Purpose |
|------|---------|
| `-u, --url URL` | Target URL (`http(s)://host[:port]`) |
| `-f, --file FILE` | File with one URL per line |
| `--db PATH` | Path to vuln YAML DB (default: `data/vulns.yaml`) |
| `--proxy URL` | HTTP(S) proxy, e.g. `http://127.0.0.1:8080` |
| `--insecure` | Skip TLS verification |
| `--timeout SECS` | Per-request timeout (default `15`) |
| `--workers N` | Concurrent module probes (default `8`) |
| `--no-modules` | Skip module scanning |
| `--json` | JSON output; suppresses banner + progress |
| `-q, --quiet` | Suppress banner + progress (keep text report) |
| `-V, --version` | Print version |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Bitrix detected, scan completed |
| `1` | Runtime error on one or more targets |
| `2` | No target given / Bitrix not detected |
| `130` | Interrupted (Ctrl-C) |

---

## Output

### Terminal (default)

Rich tables:

- **Fingerprint** — detection verdict, confidence, core version, `main` module
  version, server, `Powered-By`, generator, list of matched signals.
- **Modules** — name, version, source (`version.php`, `js_qs`, `css_qs`,
  `path_listing`, `path_403`), evidence URL.
- **Templates / Components** — names discovered in root HTML.
- **Potential vulnerabilities** — DB matches coloured by severity.

### JSON (`--json`)

```json
{
  "target": "https://target.tld",
  "fingerprint": { "is_bitrix": true, "confidence": 75, "core_version": "…", "…": "…" },
  "modules":     { "modules": [], "templates": [], "components": [] },
  "matches":     [ { "vuln": {}, "detected_version": "…" } ]
}
```

Designed for piping (`bscan.py -u … --json | jq …`).

---

## Vulnerability database

Location: `data/vulns.yaml`. Add entries as you find them.

```yaml
vulns:
  - id: BX-2022-VOTE-RCE
    title: "Vote module — unauthenticated RCE via crafted voting data"
    target: vote            # "core" or a Bitrix module name
    severity: critical      # low | medium | high | critical
    cve: CVE-2022-27228
    fixed_in: "22.0.0"      # trigger: detected < fixed_in
    # or:
    # affected: ">=20.0.0,<22.0.400"
    refs:
      - https://nvd.nist.gov/vuln/detail/CVE-2022-27228
```

Matching rules:

- `affected` takes precedence over `fixed_in`.
- Versions are parsed left-to-right as integer tuples (non-digits stripped per
  segment), so `22.0.400 > 22.0.99`.
- A vuln with neither `affected` nor `fixed_in` never matches.

---

## Project layout

```
Bscan/
├── bscan.py                  # entry shim
├── bscan/
│   ├── __init__.py
│   ├── banner.py             # ASCII logo
│   ├── cli.py                # argparse CLI + progress wiring
│   ├── fingerprint.py        # Bitrix detection + core version
│   ├── http.py               # httpx client wrapper
│   ├── modules.py            # module / template / component scan
│   ├── report.py             # Rich + JSON renderers
│   └── vulndb.py             # YAML loader + version matcher
├── data/
│   └── vulns.yaml            # seed vuln DB
├── tests/
└── requirements.txt
```

---

## Roadmap

- Expand `data/vulns.yaml` with real Bitrix CVEs.
- Grow `COMMON_MODULES` list + fingerprints for marketplace components.
- Optional output: SARIF, HTML report.
- Auth / cookie support for logged-in scanning.
