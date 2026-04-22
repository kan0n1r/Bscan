from __future__ import annotations

import json
from dataclasses import asdict
from typing import List

from rich.console import Console
from rich.table import Table

from .behavior import BehaviorResult
from .fingerprint import Fingerprint
from .http import AuthConfig
from .misconfig import Finding
from .modules import ModuleScan
from .vulndb import Match, summarize_matches


SEVERITY_STYLES = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "unknown": "white",
}


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}


def render_text(
    target: str,
    fp: Fingerprint,
    modules: ModuleScan,
    matches: List[Match],
    findings: List[Finding] | None = None,
    behavior: BehaviorResult | None = None,
    auth: AuthConfig | None = None,
) -> None:
    con = Console()
    con.rule(f"[bold]Bscan[/bold] — {target}")

    fp_tbl = Table(show_header=False, box=None, pad_edge=False)
    fp_tbl.add_column(style="cyan")
    fp_tbl.add_column()
    fp_tbl.add_row("Bitrix detected", "yes" if fp.is_bitrix else "no")
    fp_tbl.add_row("Confidence", f"{fp.confidence}%")
    fp_tbl.add_row("Core version", fp.core_version or "-")
    fp_tbl.add_row("main module version", fp.main_module_version or "-")
    if fp.hash_version:
        fp_tbl.add_row(
            "Hash-matched version",
            f"[bold green]{fp.hash_version}[/bold green] [dim]({fp.hash_source})[/dim]",
        )
    if fp.core_js_sha256:
        fp_tbl.add_row("core.js sha256", f"[dim]{fp.core_js_sha256}[/dim]")
    fp_tbl.add_row("Server", fp.server or "-")
    fp_tbl.add_row("Powered-By", fp.powered_by or "-")
    fp_tbl.add_row("Generator", fp.generator or "-")
    fp_tbl.add_row("Signals", ", ".join(fp.signals) or "-")
    if auth and auth.enabled:
        fp_tbl.add_row(
            "Auth context",
            f"authenticated [dim](headers={len(auth.headers)}, cookies={len(auth.cookies)})[/dim]",
        )
    else:
        fp_tbl.add_row("Auth context", "anonymous")
    if behavior and behavior.range:
        style = "yellow" if behavior.is_empty else "green"
        fp_tbl.add_row(
            "Behavior range",
            f"[{style}]{behavior.range}[/{style}] [dim]({len(behavior.matched_probes)} hits)[/dim]",
        )
    con.print(fp_tbl)

    if behavior and behavior.constraints:
        con.rule("Behavior signals")
        tbl = Table()
        tbl.add_column("source", style="bold")
        tbl.add_column("implies")
        for c in behavior.constraints:
            tbl.add_row(c["source"], c["implies"])
        con.print(tbl)
        if behavior.is_empty:
            con.print("[yellow]note: behavior constraints intersect to empty — probably a false-positive probe.[/yellow]")

    if modules.modules:
        con.rule("Modules")
        tbl = Table()
        tbl.add_column("name", style="bold")
        tbl.add_column("version")
        tbl.add_column("source", style="dim")
        tbl.add_column("evidence", style="dim")
        for m in sorted(modules.modules, key=lambda x: x.name):
            tbl.add_row(m.name, m.version or "-", m.source or "-", m.evidence_url or "-")
        con.print(tbl)
    if modules.templates:
        con.print(f"[cyan]Templates:[/cyan] {', '.join(modules.templates)}")
    if modules.components:
        con.print(f"[cyan]Components:[/cyan] {', '.join(modules.components)}")

    if findings:
        con.rule("Misconfigurations")
        tbl = Table()
        tbl.add_column("id", style="bold")
        tbl.add_column("severity")
        tbl.add_column("category", style="dim")
        tbl.add_column("title")
        tbl.add_column("evidence", style="dim")
        for f in sorted(findings, key=lambda x: (_SEV_ORDER.get(x.severity, 9), x.id)):
            style = SEVERITY_STYLES.get(f.severity, "white")
            tbl.add_row(
                f.id,
                f"[{style}]{f.severity}[/{style}]",
                f.category,
                f.title,
                f.evidence[:80],
            )
        con.print(tbl)

    if matches:
        risk = summarize_matches(matches)
        con.print(
            f"[bold]Risk score:[/bold] {risk.score}/100 [dim]({risk.rating}, matches={risk.matched_count})[/dim]"
        )
        con.rule("Potential vulnerabilities")
        tbl = Table()
        tbl.add_column("id", style="bold")
        tbl.add_column("severity")
        tbl.add_column("confidence")
        tbl.add_column("target")
        tbl.add_column("version")
        tbl.add_column("title")
        for m in matches:
            style = SEVERITY_STYLES.get(m.vuln.severity, "white")
            tbl.add_row(
                m.vuln.id,
                f"[{style}]{m.vuln.severity}[/{style}]",
                f"{m.confidence_label} ({m.confidence})",
                m.vuln.target,
                m.detected_version or "-",
                m.vuln.title,
            )
        con.print(tbl)
    else:
        con.print("[green]No vulnerability matches against current DB.[/green]")


def render_json(
    target: str,
    fp: Fingerprint,
    modules: ModuleScan,
    matches: List[Match],
    findings: List[Finding] | None = None,
    behavior: BehaviorResult | None = None,
    auth: AuthConfig | None = None,
) -> str:
    risk = summarize_matches(matches)
    payload = {
        "target": target,
        "request": auth.to_metadata() if auth is not None else AuthConfig().to_metadata(),
        "risk_summary": asdict(risk),
        "fingerprint": asdict(fp),
        "modules": {
            "modules": [asdict(m) for m in modules.modules],
            "templates": modules.templates,
            "components": modules.components,
        },
        "matches": [
            {
                "vuln": asdict(m.vuln),
                "detected_version": m.detected_version,
                "confidence": m.confidence,
                "confidence_label": m.confidence_label,
                "evidence_source": m.evidence_source,
                "match_reason": m.match_reason,
            }
            for m in matches
        ],
        "misconfigurations": [f.to_dict() for f in (findings or [])],
        "behavior": behavior.to_dict() if behavior else None,
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)
