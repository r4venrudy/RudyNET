import os
import sys


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.name == "nt":
        os.system("")  # enables ANSI escape handling on Windows 10+
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


_ON = _supports_color()


def _c(code: str) -> str:
    return f"\033[{code}m" if _ON else ""


class Colors:
    RESET = _c("0")
    BOLD = _c("1")
    DIM = _c("2")
    RED = _c("31")
    GREEN = _c("32")
    YELLOW = _c("33")
    BLUE = _c("34")
    CYAN = _c("36")

    INFO = f"{BLUE}[*]{RESET} "
    SUCCESS = f"{GREEN}[+]{RESET} "
    WARNING = f"{YELLOW}[!]{RESET} "
    ERROR = f"{RED}[-]{RESET} "

    BANNER = r"""
  ____            _       _   _ _____ _____
 |  _ \ _   _  __| |_   _| \ | | ____|_   _|
 | |_) | | | |/ _` | | | |  \| |  _|   | |
 |  _ <| |_| | (_| | |_| | |\  | |___  | |
 |_| \_\\__,_|\__,_|\__, |_| \_|_____| |_|
                    |___/   by r4ven.leet
"""

    @classmethod
    def print_banner(cls) -> None:
        print(f"{cls.CYAN}{cls.BANNER}{cls.RESET}")

    @classmethod
    def grade(cls, grade: str) -> str:
        color = {"A": cls.GREEN, "B": cls.GREEN, "C": cls.YELLOW, "D": cls.YELLOW}.get(grade[:1], cls.RED)
        return f"{cls.BOLD}{color}{grade}{cls.RESET}"
