"""Terminal colors.

Uses colorama on Windows, falls back to raw ANSI codes.
Either way the program keeps working.
"""

try:
    from colorama import init as _colorama_init, Fore, Style
    _colorama_init(autoreset=True)
    RED = Fore.RED
    BRIGHT_RED = Fore.LIGHTRED_EX
    GREEN = Fore.GREEN
    BRIGHT_GREEN = Fore.LIGHTGREEN_EX
    YELLOW = Fore.YELLOW
    CYAN = Fore.CYAN
    WHITE = Fore.WHITE
    DIM = Style.DIM
    BRIGHT = Style.BRIGHT
    RESET = Style.RESET_ALL
    BLOOD = Fore.RED + Style.BRIGHT
except ImportError:  # bare ANSI when colorama is missing
    RED = "\033[31m"
    BRIGHT_RED = "\033[91m"
    GREEN = "\033[32m"
    BRIGHT_GREEN = "\033[92m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    DIM = "\033[2m"
    BRIGHT = "\033[1m"
    RESET = "\033[0m"
    BLOOD = "\033[91m\033[1m"


def critical(text: str) -> str:
    """Bright red highlight for critical findings."""
    return f"{BLOOD}{BRIGHT}{text}{RESET}"


def success(text: str) -> str:
    return f"{BRIGHT_GREEN}{text}{RESET}"


def info(text: str) -> str:
    return f"{CYAN}{text}{RESET}"


def warn(text: str) -> str:
    return f"{YELLOW}{text}{RESET}"


def danger(text: str) -> str:
    return f"{RED}{text}{RESET}"
