"""
Shared terminal UI utilities – colors, banners, prompts, spinners.
"""

import sys
import time
import threading
import textwrap
import shutil

# ---------------------------------------------------------------------------
# ANSI color codes
# ---------------------------------------------------------------------------
class C:
    RED     = "\033[0;31m"
    LRED    = "\033[1;31m"
    GREEN   = "\033[0;32m"
    LGREEN  = "\033[1;32m"
    YELLOW  = "\033[1;33m"
    BLUE    = "\033[0;34m"
    LBLUE   = "\033[1;34m"
    CYAN    = "\033[0;36m"
    LCYAN   = "\033[1;36m"
    MAGENTA = "\033[0;35m"
    LMAG    = "\033[1;35m"
    WHITE   = "\033[1;37m"
    GRAY    = "\033[0;37m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

    @staticmethod
    def strip(text: str) -> str:
        """Remove all ANSI codes from a string."""
        import re
        return re.sub(r'\033\[[0-9;]*m', '', text)


def _w() -> int:
    return shutil.get_terminal_size((100, 40)).columns


# ---------------------------------------------------------------------------
# Print helpers
# ---------------------------------------------------------------------------
def banner(text: str, color: str = C.CYAN):
    w = min(_w(), 80)
    print(f"\n{color}{'─' * w}{C.RESET}")
    print(f"{color}{C.BOLD}  {text}{C.RESET}")
    print(f"{color}{'─' * w}{C.RESET}")


def section(text: str):
    print(f"\n{C.LBLUE}{'━' * 4} {C.BOLD}{text}{C.RESET} {C.LBLUE}{'━' * (min(_w(),70) - len(text) - 6)}{C.RESET}")


def info(msg: str):    print(f"{C.LGREEN}[+]{C.RESET} {msg}")
def warn(msg: str):    print(f"{C.YELLOW}[!]{C.RESET} {msg}")
def error(msg: str):   print(f"{C.LRED}[-]{C.RESET} {msg}")
def debug(msg: str):   print(f"{C.GRAY}[.]{C.RESET} {C.DIM}{msg}{C.RESET}")
def step(msg: str):    print(f"\n{C.LCYAN}[>]{C.RESET} {C.BOLD}{msg}{C.RESET}")
def alert(msg: str):   print(f"{C.LRED}[!]{C.RESET} {C.LRED}{C.BOLD}{msg}{C.RESET}")
def success(msg: str): print(f"{C.LGREEN}[✓]{C.RESET} {C.LGREEN}{msg}{C.RESET}")
def packet(msg: str):  print(f"{C.MAGENTA}[→]{C.RESET} {C.DIM}{msg}{C.RESET}")


def rule(char: str = "─", color: str = C.GRAY):
    print(f"{color}{char * min(_w(), 80)}{C.RESET}")


def header_box(lines: list[str], color: str = C.CYAN):
    """Print a box around a list of lines."""
    w = max(len(C.strip(l)) for l in lines) + 4
    w = min(w, 80)
    print(f"{color}┌{'─' * w}┐{C.RESET}")
    for line in lines:
        stripped_len = len(C.strip(line))
        padding = w - stripped_len - 2
        print(f"{color}│{C.RESET} {line}{' ' * padding} {color}│{C.RESET}")
    print(f"{color}└{'─' * w}┘{C.RESET}")


def guide_box(title: str, content: str, color: str = C.LBLUE):
    """Render a formatted guide block."""
    w = min(_w(), 80)
    print(f"\n{color}╔{'═' * (w-2)}╗{C.RESET}")
    print(f"{color}║{C.RESET} {C.BOLD}{title:<{w-4}}{C.RESET} {color}║{C.RESET}")
    print(f"{color}╠{'═' * (w-2)}╣{C.RESET}")
    for line in content.strip().split("\n"):
        wrapped = textwrap.wrap(line, width=w-4) or [""]
        for wline in wrapped:
            print(f"{color}║{C.RESET} {wline:<{w-4}} {color}║{C.RESET}")
    print(f"{color}╚{'═' * (w-2)}╝{C.RESET}")


def tag(label: str, value: str, lcolor=C.CYAN, vcolor=C.WHITE):
    print(f"  {lcolor}{label:<18}{C.RESET} {vcolor}{value}{C.RESET}")


# ---------------------------------------------------------------------------
# Spinner
# ---------------------------------------------------------------------------
class Spinner:
    FRAMES = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]

    def __init__(self, message: str = "Working", color: str = C.CYAN):
        self.message = message
        self.color   = color
        self._stop   = threading.Event()
        self._thread = threading.Thread(target=self._spin, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *_):
        self._stop.set()
        self._thread.join()
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()

    def _spin(self):
        i = 0
        while not self._stop.is_set():
            frame = self.FRAMES[i % len(self.FRAMES)]
            sys.stdout.write(f"\r{self.color}{frame}{C.RESET} {self.message} ")
            sys.stdout.flush()
            time.sleep(0.1)
            i += 1


# ---------------------------------------------------------------------------
# Input helpers
# ---------------------------------------------------------------------------
def ask(prompt: str, default: str = "") -> str:
    display = f"  {C.CYAN}?{C.RESET} {prompt}"
    if default:
        display += f" {C.DIM}[{default}]{C.RESET}"
    display += f" {C.YELLOW}▶{C.RESET} "
    try:
        val = input(display).strip()
        return val if val else default
    except (EOFError, KeyboardInterrupt):
        print()
        return default


def confirm(prompt: str, default: bool = False) -> bool:
    hint = "Y/n" if default else "y/N"
    val  = ask(f"{prompt} ({hint})", "y" if default else "n")
    return val.lower() in ("y", "yes")


def choose(prompt: str, options: list[str], default: int = 0) -> int:
    """Present numbered options, return 0-based index."""
    print(f"\n  {C.BOLD}{prompt}{C.RESET}")
    for i, opt in enumerate(options):
        marker = f"{C.LGREEN}▶{C.RESET}" if i == default else " "
        print(f"  {marker} {C.CYAN}{i+1}{C.RESET}) {opt}")
    while True:
        raw = ask(f"Choice [1-{len(options)}]", str(default + 1))
        try:
            idx = int(raw) - 1
            if 0 <= idx < len(options):
                return idx
        except ValueError:
            pass
        warn(f"Enter a number between 1 and {len(options)}")


# ---------------------------------------------------------------------------
# Progress bar
# ---------------------------------------------------------------------------
def progress(current: int, total: int, label: str = "", width: int = 40):
    pct  = current / total if total else 0
    done = int(width * pct)
    bar  = f"{C.LGREEN}{'█' * done}{C.GRAY}{'░' * (width - done)}{C.RESET}"
    sys.stdout.write(f"\r  {bar} {C.BOLD}{pct:5.1%}{C.RESET}  {C.DIM}{label}{C.RESET}  ")
    sys.stdout.flush()
    if current >= total:
        print()


# ---------------------------------------------------------------------------
# Status table
# ---------------------------------------------------------------------------
def status_table(rows: list[tuple[str, str, str]]):
    """Print a simple 3-column status table: (label, value, status)."""
    col1 = max(len(r[0]) for r in rows) + 2
    col2 = max(len(r[1]) for r in rows) + 2
    print()
    for label, value, status in rows:
        sc = C.LGREEN if "ok" in status.lower() or "✓" in status else \
             C.YELLOW  if "warn" in status.lower() else C.LRED
        print(f"  {C.CYAN}{label:<{col1}}{C.RESET}"
              f"{C.WHITE}{value:<{col2}}{C.RESET}"
              f"{sc}{status}{C.RESET}")
    print()


# ---------------------------------------------------------------------------
# Pause / countdown
# ---------------------------------------------------------------------------
def pause(msg: str = "Press ENTER to continue"):
    try:
        input(f"\n  {C.DIM}{msg}{C.RESET} ")
    except (EOFError, KeyboardInterrupt):
        print()


def countdown(seconds: int, msg: str = "Starting in"):
    for i in range(seconds, 0, -1):
        sys.stdout.write(f"\r  {C.YELLOW}{msg} {i}s...{C.RESET}  ")
        sys.stdout.flush()
        time.sleep(1)
    sys.stdout.write("\r\033[K")
    sys.stdout.flush()
