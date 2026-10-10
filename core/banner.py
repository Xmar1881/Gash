"""Startup banner — ASCII art logo."""

import shutil
import sys
from core.colors import RED, GREEN, BRIGHT_RED, BRIGHT_GREEN, DIM, BRIGHT, RESET, WHITE

LOGO_LINES = [
    r"  ██████╗  █████╗ ███████╗██╗  ██╗",
    r" ██╔════╝ ██╔══██╗██╔════╝██║  ██║",
    r" ██║  ███╗███████║███████╗███████║",
    r" ██║   ██║██╔══██║╚════██║██╔══██║",
    r" ╚██████╔╝██║  ██║███████║██║  ██║",
    r"  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝",
]

# ASCII fallback so narrow Windows codepages don't blow up
LOGO_ASCII = [
    r"   ____    _    ____  _   _ ",
    r"  / ___|  / \  / ___|| | | |",
    r" | |  _  / _ \ \___ \| |_| |",
    r" | |_| |/ ___ \ ___) |  _  |",
    r"  \____/_/   \_\____/|_| |_|",
]

MOTTO = "[ GASH // Vulnerability & Penetration Engine ]"
WARNING = "(!) Authorized / legal testing only. You are responsible for its use."


def _supports_unicode() -> bool:
    enc = (sys.stdout.encoding or "").lower()
    try:
        "█─╔".encode(enc)
        return True
    except Exception:
        return False


def _safe_print(text: str) -> None:
    """cp1254 gibi dar codepagelerde patlamadan bas."""
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode("ascii", "replace").decode("ascii"))


def _colorize_logo(logo: list[str] | None = None) -> list[str]:
    """Paint the GASH letters in a red/green gradient."""
    logo = logo or LOGO_LINES
    out = []
    for i, line in enumerate(logo):
        # Top rows red, bottom rows green
        color = BRIGHT_RED if i < len(logo) // 2 else BRIGHT_GREEN
        out.append(f"{BRIGHT}{color}{line}{RESET}")
    return out


def show_banner(version: str = "0.6.0") -> None:
    """Print only the banner, nothing else. Skipped with --no-banner."""
    # Force UTF-8 — avoids cp1254 breakage on Windows
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    width = shutil.get_terminal_size(fallback=(80, 24)).columns

    logo = LOGO_LINES if _supports_unicode() else LOGO_ASCII
    _safe_print("")
    for line in _colorize_logo(logo):
        # Center when wide, don't overflow narrow terminals
        _safe_print(line.center(width) if width > 60 else line)

    # Motto with a red-framed feel
    motto = f"{BRIGHT}{RED}{MOTTO}{RESET}"
    _safe_print(f"\n{motto.center(width + 10) if width > 60 else motto}")

    sub = (
        f"{DIM}{WHITE}v{version}  {DIM}//{RESET}  "
        f"{GREEN}fast{RESET} {DIM}|{RESET} "
        f"{GREEN}modular{RESET} {DIM}|{RESET} "
        f"{RED}thorough{RESET}"
    )
    _safe_print(f"{sub.center(width + 10) if width > 60 else sub}")
    byline = f"{DIM}developed by {WHITE}Xmar1881{RESET}"
    _safe_print(f"{byline.center(width + 10) if width > 60 else byline}\n")

    _safe_print(f"  {DIM}{WARNING}{RESET}\n")

    bar_char = "─" if _supports_unicode() else "-"
    bar = f"{DIM}{bar_char * min(width - 4, 66)}{RESET}"
    _safe_print(f"  {bar}\n")
