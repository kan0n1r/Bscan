from __future__ import annotations

import json
from dataclasses import asdict
from typing import List

from rich.console import Console
from rich.table import Table

from .fingerprint import Fingerprint
from .modules import ModuleScan
from .vulndb import Match


SEVERITY_STYLES = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "unknown": "white",
}


def render_text(
    target: str,
    fp: Fingerprint,
    modules: ModuleScan,
    matches: List[Match],
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
    fp_tbl.add_row("Server", fp.server or "-")
    fp_tbl.add_row("Powered-By", fp.powered_by or "-")
    fp_tbl.add_row("Generator", fp.generator or "-")
    fp_tbl.add_row("Signals", ", ".join(fp.signals) or "-")
    con.print(fp_tbl)

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

    if matches:
        con.rule("Potential vulnerabilities")
        tbl = Table()
        tbl.add_column("id", style="bold")
        tbl.add_column("severity")
        tbl.add_column("target")
        tbl.add_column("version")
        tbl.add_column("title")
        for m in matches:
            style = SEVERITY_STYLES.get(m.vuln.severity, "white")
            tbl.add_row(
                m.vuln.id,
                f"[{style}]{m.vuln.severity}[/{style}]",
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
) -> str:
    payload = {
        "target": target,
        "fingerprint": asdict(fp),
        "modules": {
            "modules": [asdict(m) for m in modules.modules],
            "templates": modules.templates,
            "components": modules.components,
        },
        "matches": [
            {"vuln": asdict(m.vuln), "detected_version": m.detected_version}
            for m in matches
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)
