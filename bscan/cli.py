from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List

from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from . import __version__
from .banner import print_banner, stderr_console
from .fingerprint import fingerprint
from .hashes import HashDB
from .http import Client
from .misconfig import Check, Finding, audit_cookies, audit_headers, load_checks, run_checks
from .modules import COMMON_MODULES, ModuleScan, scan_modules
from .report import render_json, render_text
from .vulndb import Match, VulnDB


DEFAULT_DB = Path(__file__).resolve().parent.parent / "data" / "vulns.yaml"
DEFAULT_HASH_DB = Path(__file__).resolve().parent.parent / "data" / "core_js_hashes.yaml"
DEFAULT_MISCONFIG = Path(__file__).resolve().parent.parent / "data" / "misconfig.yaml"


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="bscan",
        description="Fingerprint and scan 1C-Bitrix sites for modules, misconfigs, and known vulnerabilities.",
    )
    p.add_argument("-u", "--url", help="Target URL (http(s)://host[:port])")
    p.add_argument("-f", "--file", help="File with one URL per line")
    p.add_argument("--db", default=str(DEFAULT_DB), help="Path to vuln YAML db")
    p.add_argument("--hash-db", default=str(DEFAULT_HASH_DB), help="Path to static-asset hash YAML db")
    p.add_argument("--misconfig-db", default=str(DEFAULT_MISCONFIG), help="Path to misconfig YAML checks")
    p.add_argument("--proxy", help="HTTP(S) proxy, e.g. http://127.0.0.1:8080")
    p.add_argument("--insecure", action="store_true", help="Skip TLS verification")
    p.add_argument("--timeout", type=float, default=15.0, help="Per-request timeout seconds")
    p.add_argument("--workers", type=int, default=8, help="Concurrent module probes")
    p.add_argument("--no-modules", action="store_true", help="Skip module scanning")
    p.add_argument("--no-misconfig", action="store_true", help="Skip misconfiguration checks")
    p.add_argument("--json", action="store_true", help="JSON output (suppresses banner/progress)")
    p.add_argument("-q", "--quiet", action="store_true", help="Suppress banner and progress")
    p.add_argument("-V", "--version", action="version", version=f"bscan {__version__}")
    return p


def _load_targets(args: argparse.Namespace) -> List[str]:
    targets: List[str] = []
    if args.url:
        targets.append(args.url)
    if args.file:
        for line in Path(args.file).read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    return targets


def _scan_one(
    target: str,
    args: argparse.Namespace,
    db: VulnDB,
    hash_db: HashDB,
    checks: List[Check],
    show_progress: bool,
) -> int:
    with Client(
        base_url=target,
        timeout=args.timeout,
        verify=not args.insecure,
        proxy=args.proxy,
    ) as client:
        if show_progress:
            rc = _scan_with_progress(target, client, args, db, hash_db, checks)
        else:
            rc = _scan_quiet(target, client, args, db, hash_db, checks)
    return rc


def _scan_quiet(
    target: str,
    client: Client,
    args: argparse.Namespace,
    db: VulnDB,
    hash_db: HashDB,
    checks: List[Check],
) -> int:
    fp = fingerprint(client, hash_db=hash_db)
    root = client.get("/")
    mods = scan_modules(client, root, workers=args.workers) if not args.no_modules else ModuleScan()
    findings = _run_misconfig(client, root, checks) if not args.no_misconfig else []
    matches = _collect_matches(fp, mods, db)
    if args.json:
        print(render_json(target, fp, mods, matches, findings))
    else:
        render_text(target, fp, mods, matches, findings)
    return 0 if fp.is_bitrix else 2


def _scan_with_progress(
    target: str,
    client: Client,
    args: argparse.Namespace,
    db: VulnDB,
    hash_db: HashDB,
    checks: List[Check],
) -> int:
    con = stderr_console()
    total_modules = 0 if args.no_modules else len(COMMON_MODULES)
    fp_total = 4 + len(hash_db.paths) + 1
    total_checks = 0 if args.no_misconfig else len(checks)

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold]{task.description}[/bold]"),
        BarColumn(bar_width=30),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TextColumn("{task.fields[detail]}"),
        console=con,
        transient=True,
    ) as progress:
        fp_task = progress.add_task(
            f"fingerprint {target}", total=fp_total, detail=""
        )

        def on_fp_step(name: str) -> None:
            progress.update(fp_task, advance=1, detail=name)

        fp = fingerprint(client, on_step=on_fp_step, hash_db=hash_db)
        progress.update(fp_task, completed=fp_total, detail="done")

        root = client.get("/")

        if args.no_modules:
            mods = ModuleScan()
        else:
            mod_task = progress.add_task(
                "modules", total=total_modules, detail=""
            )

            def on_probe(name: str, found: bool) -> None:
                marker = "[green]+[/green]" if found else "[dim]-[/dim]"
                progress.update(mod_task, advance=1, detail=f"{marker} {name}")

            mods = scan_modules(client, root, workers=args.workers, on_probe=on_probe)

        if args.no_misconfig:
            findings: List[Finding] = []
        else:
            misc_task = progress.add_task(
                "misconfig", total=total_checks, detail=""
            )

            def on_check(cid: str, hit: bool) -> None:
                marker = "[red]![/red]" if hit else "[dim]·[/dim]"
                progress.update(misc_task, advance=1, detail=f"{marker} {cid}")

            findings = _run_misconfig(client, root, checks, on_check=on_check)

    matches = _collect_matches(fp, mods, db)
    if args.json:
        print(render_json(target, fp, mods, matches, findings))
    else:
        render_text(target, fp, mods, matches, findings)
    return 0 if fp.is_bitrix else 2


def _run_misconfig(client, root, checks, on_check=None) -> List[Finding]:
    findings: List[Finding] = []
    findings.extend(run_checks(client, checks, on_check=on_check))
    findings.extend(audit_headers(root))
    findings.extend(audit_cookies(root))
    return findings


def _collect_matches(fp, mods: ModuleScan, db: VulnDB) -> List[Match]:
    matches: List[Match] = []
    core_version = fp.best_core_version
    if core_version:
        matches += db.match("core", core_version)
        matches += db.match("main", core_version)
    for m in mods.modules:
        if m.version:
            matches += db.match(m.name, m.version)
    return matches


def main(argv: List[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    targets = _load_targets(args)
    if not targets:
        print("error: provide -u URL or -f FILE", file=sys.stderr)
        return 2

    show_banner = not (args.json or args.quiet)
    show_progress = not (args.json or args.quiet) and sys.stderr.isatty()

    if show_banner:
        print_banner()

    db = VulnDB.load(Path(args.db))
    hash_db = HashDB.load(Path(args.hash_db))
    checks = [] if args.no_misconfig else load_checks(Path(args.misconfig_db))

    rc = 0
    for t in targets:
        try:
            rc |= _scan_one(t, args, db, hash_db, checks, show_progress=show_progress)
        except KeyboardInterrupt:
            print("aborted", file=sys.stderr)
            return 130
        except Exception as e:  # noqa: BLE001
            print(f"error scanning {t}: {e}", file=sys.stderr)
            rc |= 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
