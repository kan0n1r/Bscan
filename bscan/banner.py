from __future__ import annotations

import sys

from rich.console import Console

from . import __version__


LOGO = r"""
 ____
| __ )  ___  ___ __ _ _ __
|  _ \ / __|/ __/ _` | '_ \
| |_) |\__ \ (_| (_| | | | |
|____/ |___/\___\__,_|_| |_|
"""

TAGLINE = "1C-Bitrix plugin & version scanner"


def print_banner(console: Console | None = None) -> None:
    con = console or Console(stderr=True)
    con.print(f"[bold cyan]{LOGO}[/bold cyan]", highlight=False)
    con.print(
        f"  [bold]{TAGLINE}[/bold]  [dim]v{__version__}[/dim]",
        highlight=False,
    )
    con.print(
        "  [dim]github.com/bscan  —  use only on systems you are authorized to test[/dim]\n",
        highlight=False,
    )


def stderr_console() -> Console:
    return Console(stderr=True, force_terminal=sys.stderr.isatty())
