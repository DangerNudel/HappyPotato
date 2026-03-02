"""
Base class for all DNS attack lab modules.
Every module inherits from LabModule and implements:
  - GUIDE: str         — embedded markdown-style guide
  - setup()            — automated environment setup
  - run()              — execute the demonstration
  - teardown()         — cleanup after demo
"""

import shutil
import signal
import textwrap
import traceback
from shared.ui import *
from shared.prereqs import check_root


class LabModule:
    NAME:          str = "Unnamed Module"
    DESCRIPTION:   str = ""
    MITRE:         str = ""
    DIFFICULTY:    str = "Intermediate"
    REQUIRES_ROOT: bool = True
    GUIDE:         str = ""

    _running: bool = False

    def __init__(self):
        self._orig_sigint = None

    # ------------------------------------------------------------------
    def show_overview(self):
        banner(f"MODULE: {self.NAME}", C.LCYAN)
        print()
        tag("Description",   self.DESCRIPTION)
        tag("MITRE ATT&CK",  self.MITRE,      C.RED,    C.LRED)
        tag("Difficulty",    self.DIFFICULTY,  C.YELLOW, C.YELLOW)
        tag("Root Required", "Yes" if self.REQUIRES_ROOT else "No")
        print()
        if self.GUIDE:
            self._render_guide(self.GUIDE)

    def _render_guide(self, guide: str):
        w      = min(shutil.get_terminal_size((100, 40)).columns, 82)
        in_code = False
        for line in guide.split("\n"):
            if line.startswith("```"):
                in_code = not in_code
                print(f"  {C.DIM}{'─' * (w - 4)}{C.RESET}")
                continue
            if in_code:
                print(f"  {C.LGREEN}{line}{C.RESET}")
                continue
            if line.startswith("## "):
                section(line[3:])
            elif line.startswith("# "):
                banner(line[2:], C.CYAN)
            elif line.startswith("### "):
                print(f"\n  {C.BOLD}{C.YELLOW}{line[4:]}{C.RESET}")
            elif line.startswith(("- ", "* ")):
                print(f"  {C.CYAN}•{C.RESET} {line[2:]}")
            elif line.startswith("> "):
                print(f"  {C.YELLOW}│{C.RESET} {C.DIM}{line[2:]}{C.RESET}")
            elif line.strip():
                for wl in (textwrap.wrap(line, width=w - 4) or [line]):
                    print(f"  {wl}")
            else:
                print()

    def prompt_setup(self) -> bool:
        section("Automated Setup")
        info(f"Running setup for: {self.NAME}")
        try:
            return self.setup()
        except KeyboardInterrupt:
            warn("Setup interrupted.")
            return False
        except Exception as e:
            error(f"Setup failed: {e}")
            traceback.print_exc()
            return False

    def prompt_run(self):
        section("Running Demonstration")
        self._running = True
        self._orig_sigint = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, self._handle_interrupt)
        try:
            self.run()
        except KeyboardInterrupt:
            print()
            warn("Demo interrupted by user.")
        except Exception as e:
            error(f"Demo error: {e}")
            traceback.print_exc()
        finally:
            self._running = False
            signal.signal(signal.SIGINT, self._orig_sigint or signal.SIG_DFL)
            try:
                self.teardown()
            except Exception:
                pass

    def _handle_interrupt(self, sig, frame):
        print()
        warn("Stopping demo...")
        self._running = False
        raise KeyboardInterrupt

    def setup(self) -> bool:
        success("No special setup required.")
        return True

    def run(self):
        warn("No run() implementation.")

    def teardown(self):
        pass

    @staticmethod
    def require_root() -> bool:
        return check_root(require=True)

    @staticmethod
    def print_packet_hex(data: bytes, max_bytes: int = 64):
        chunk = data[:max_bytes]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        asc_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"  {C.DIM}{hex_str:<47}  {asc_str}{C.RESET}")
        if len(data) > max_bytes:
            print(f"  {C.DIM}... ({len(data)} bytes total){C.RESET}")
