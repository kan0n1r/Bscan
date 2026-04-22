from __future__ import annotations

import argparse
import datetime as _dt
import re as _re
import sys
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse

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
from .behavior import BehaviorConfig, BehaviorResult, load_config as load_behavior, run_behavior
from .hashes import HashDB
from .http import AuthConfig, Client
from .misconfig import Check, Finding, audit_cookies, audit_headers, load_checks, run_checks
from .modules import COMMON_MODULES, DEEP_MODULES, ModuleScan, scan_modules
from .report import render_json, render_text
from .vulndb import Match, VulnDB


DEFAULT_DB = Path(__file__).resolve().parent.parent / "data" / "vulns.yaml"
DEFAULT_HASH_DB = Path(__file__).resolve().parent.parent / "data" / "core_js_hashes.yaml"
DEFAULT_MISCONFIG = Path(__file__).resolve().parent.parent / "data" / "misconfig.yaml"
DEFAULT_BEHAVIOR = Path(__file__).resolve().parent.parent / "data" / "behavior.yaml"
DEFAULT_PROFILE = "default"


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
    p.add_argument("--behavior-db", default=str(DEFAULT_BEHAVIOR), help="Path to behavior YAML probes")
    p.add_argument("--proxy", help="HTTP(S) proxy, e.g. http://127.0.0.1:8080")
    p.add_argument("--header", action="append", default=[], help="Attach request header, e.g. 'Authorization: Bearer ...'")
    p.add_argument("--cookie", action="append", default=[], help="Attach cookie, e.g. 'PHPSESSID=...'")
    p.add_argument("--cookie-file", help="Load cookies from a file (one name=value or Cookie: ... line per entry)")
    p.add_argument("--insecure", action="store_true", help="Skip TLS verification")
    p.add_argument("--timeout", type=float, default=15.0, help="Per-request timeout seconds")
    p.add_argument("--workers", type=int, default=8, help="Concurrent module probes")
    p.add_argument("--profile", choices=["fast", "default", "deep"], default=DEFAULT_PROFILE, help="Scan depth profile")
    p.add_argument("--no-modules", action="store_true", help="Skip module scanning")
    p.add_argument("--no-misconfig", action="store_true", help="Skip misconfiguration checks")
    p.add_argument("--no-behavior", action="store_true", help="Skip behavioral version fingerprinting")
    p.add_argument("--json", action="store_true", help="JSON output (suppresses banner/progress)")
    p.add_argument("-o", "--output", help="Write JSON report to PATH (file or directory). Implies --json semantics for the file.")
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


def _parse_header(value: str) -> tuple[str, str]:
    if ":" not in value:
        raise ValueError(f"invalid header {value!r}; expected 'Name: Value'")
    name, raw = value.split(":", 1)
    name = name.strip()
    raw = raw.strip()
    if not name or not raw:
        raise ValueError(f"invalid header {value!r}; expected non-empty name and value")
    return name, raw


def _parse_cookie(value: str) -> tuple[str, str]:
    if "=" not in value:
        raise ValueError(f"invalid cookie {value!r}; expected 'name=value'")
    name, raw = value.split("=", 1)
    name = name.strip()
    if not name:
        raise ValueError(f"invalid cookie {value!r}; expected non-empty cookie name")
    return name, raw.strip()


def _parse_cookie_line(line: str) -> List[tuple[str, str]]:
    if line.lower().startswith("cookie:"):
        line = line.split(":", 1)[1].strip()
    parts = [part.strip() for part in line.split(";") if part.strip()]
    return [_parse_cookie(part) for part in parts]


def _build_auth_config(args: argparse.Namespace) -> AuthConfig:
    headers: dict[str, str] = {}
    cookies: dict[str, str] = {}

    for raw in args.header:
        name, value = _parse_header(raw)
        headers[name] = value

    for raw in args.cookie:
        name, value = _parse_cookie(raw)
        cookies[name] = value

    if args.cookie_file:
        for line in Path(args.cookie_file).read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            for name, value in _parse_cookie_line(line):
                cookies[name] = value

    return AuthConfig(headers=headers, cookies=cookies)


def _profile_candidates(profile: str) -> Optional[List[str]]:
    if profile == "fast":
        return []
    if profile == "deep":
        return sorted(set(COMMON_MODULES) | set(DEEP_MODULES))
    return None


def _profile_workers(profile: str, workers: int) -> int:
    if profile == "deep":
        return max(workers, 12)
    if profile == "fast":
        return min(workers, 4)
    return workers


def _scan_modules_enabled(args: argparse.Namespace) -> bool:
    return not args.no_modules


def _misconfig_enabled(args: argparse.Namespace) -> bool:
    return not args.no_misconfig and getattr(args, "profile", DEFAULT_PROFILE) != "fast"


def _behavior_enabled(args: argparse.Namespace) -> bool:
    return not args.no_behavior and getattr(args, "profile", DEFAULT_PROFILE) != "fast"


def _scan_one(
    target: str,
    args: argparse.Namespace,
    db: VulnDB,
    hash_db: HashDB,
    checks: List[Check],
    behavior: BehaviorConfig,
    show_progress: bool,
) -> int:
    with Client(
        base_url=target,
        timeout=args.timeout,
        verify=not args.insecure,
        proxy=args.proxy,
        auth=args.auth,
    ) as client:
        if show_progress:
            rc = _scan_with_progress(target, client, args, db, hash_db, checks, behavior)
        else:
            rc = _scan_quiet(target, client, args, db, hash_db, checks, behavior)
    return rc


def _scan_quiet(
    target: str,
    client: Client,
    args: argparse.Namespace,
    db: VulnDB,
    hash_db: HashDB,
    checks: List[Check],
    behavior: BehaviorConfig,
) -> int:
    fp = fingerprint(client, hash_db=hash_db)
    root = client.get("/")
    if _scan_modules_enabled(args):
        mods = scan_modules(
            client,
            root,
            candidates=_profile_candidates(args.profile),
            workers=_profile_workers(args.profile, args.workers),
        )
    else:
        mods = ModuleScan()
    findings = _run_misconfig(client, root, checks) if _misconfig_enabled(args) else []
    beh = (
        run_behavior(client, behavior, root=root)
        if _behavior_enabled(args) and behavior.enabled
        else None
    )
    matches = _collect_matches(fp, mods, db)
    _emit(target, args, fp, mods, matches, findings, beh, auth=args.auth)
    return 0 if fp.is_bitrix else 2


def _scan_with_progress(
    target: str,
    client: Client,
    args: argparse.Namespace,
    db: VulnDB,
    hash_db: HashDB,
    checks: List[Check],
    behavior: BehaviorConfig,
) -> int:
    con = stderr_console()
    module_candidates = _profile_candidates(args.profile)
    total_modules = 0 if not _scan_modules_enabled(args) else len(module_candidates or COMMON_MODULES)
    fp_total = 4 + len(hash_db.paths) + 1
    total_checks = 0 if not _misconfig_enabled(args) else len(checks)

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

        if not _scan_modules_enabled(args):
            mods = ModuleScan()
        else:
            mod_task = progress.add_task(
                "modules", total=total_modules, detail=""
            )

            def on_probe(name: str, found: bool) -> None:
                marker = "[green]+[/green]" if found else "[dim]-[/dim]"
                progress.update(mod_task, advance=1, detail=f"{marker} {name}")

            mods = scan_modules(
                client,
                root,
                candidates=module_candidates,
                workers=_profile_workers(args.profile, args.workers),
                on_probe=on_probe,
            )

        if not _misconfig_enabled(args):
            findings: List[Finding] = []
        else:
            misc_task = progress.add_task(
                "misconfig", total=total_checks, detail=""
            )

            def on_check(cid: str, hit: bool) -> None:
                marker = "[red]![/red]" if hit else "[dim]·[/dim]"
                progress.update(misc_task, advance=1, detail=f"{marker} {cid}")

            findings = _run_misconfig(client, root, checks, on_check=on_check)

        beh: Optional[BehaviorResult] = None
        if _behavior_enabled(args) and behavior.enabled:
            if behavior.total_probes:
                beh_task = progress.add_task(
                    "behavior", total=behavior.total_probes, detail=""
                )

                def on_beh(pid: str, hit: bool) -> None:
                    marker = "[green]✓[/green]" if hit else "[dim]·[/dim]"
                    progress.update(beh_task, advance=1, detail=f"{marker} {pid}")

                beh = run_behavior(client, behavior, root=root, on_probe=on_beh)
            else:
                beh = run_behavior(client, behavior, root=root)

    matches = _collect_matches(fp, mods, db)
    _emit(target, args, fp, mods, matches, findings, beh, auth=args.auth)
    return 0 if fp.is_bitrix else 2


_SAFE_HOST_RE = _re.compile(r"[^a-z0-9._-]+", _re.I)


def _report_path(base: str, target: str) -> Path:
    p = Path(base).expanduser()
    if p.exists() and p.is_dir():
        host = urlparse(target).hostname or "target"
        host = _SAFE_HOST_RE.sub("_", host)
        ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        return p / f"{host}-{ts}.json"
    if base.endswith("/") or base.endswith(("\\",)):
        p.mkdir(parents=True, exist_ok=True)
        host = urlparse(target).hostname or "target"
        host = _SAFE_HOST_RE.sub("_", host)
        ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        return p / f"{host}-{ts}.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _save_summary(path: Path, target: str, fp, mods: ModuleScan,
                  matches: List[Match], findings: List[Finding],
                  beh: Optional[BehaviorResult]) -> str:
    parts = [f"saved {path}"]
    parts.append(f"bitrix={'yes' if fp.is_bitrix else 'no'}")
    ver = fp.best_core_version
    if ver:
        parts.append(f"ver={ver}")
    if beh and beh.range:
        parts.append(f"range={beh.range}")
    parts.append(f"modules={len(mods.modules)}")
    parts.append(f"misconfigs={len(findings)}")
    parts.append(f"vulns={len(matches)}")
    return " ".join(parts)


def _emit(target, args, fp, mods, matches, findings, beh, auth: AuthConfig) -> None:
    payload = render_json(target, fp, mods, matches, findings, beh, auth=auth)
    if args.json:
        print(payload)
    else:
        render_text(target, fp, mods, matches, findings, beh, auth=auth)
    if args.output:
        out = _report_path(args.output, target)
        out.write_text(payload)
        print(_save_summary(out, target, fp, mods, matches, findings, beh), file=sys.stderr)


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
        if fp.hash_version:
            source = "hash_match"
        elif fp.main_module_version:
            source = "core_js"
        elif fp.core_version:
            source = "generator"
        else:
            source = "unknown"
        matches += db.match("core", core_version, evidence_source=source)
        matches += db.match("main", core_version, evidence_source=source)
    for m in mods.modules:
        if m.version:
            matches += db.match(m.name, m.version, evidence_source=m.source or "unknown")
    return matches


def main(argv: List[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    targets = _load_targets(args)
    if not targets:
        print("error: provide -u URL or -f FILE", file=sys.stderr)
        return 2
    try:
        args.auth = _build_auth_config(args)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    show_banner = not (args.json or args.quiet)
    show_progress = not (args.json or args.quiet) and sys.stderr.isatty()

    if show_banner:
        print_banner()

    db = VulnDB.load(Path(args.db))
    hash_db = HashDB.load(Path(args.hash_db))
    checks = [] if args.no_misconfig else load_checks(Path(args.misconfig_db))
    behavior = BehaviorConfig() if args.no_behavior else load_behavior(Path(args.behavior_db))

    rc = 0
    for t in targets:
        try:
            rc |= _scan_one(t, args, db, hash_db, checks, behavior, show_progress=show_progress)
        except KeyboardInterrupt:
            print("aborted", file=sys.stderr)
            return 130
        except Exception as e:  # noqa: BLE001
            print(f"error scanning {t}: {e}", file=sys.stderr)
            rc |= 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
