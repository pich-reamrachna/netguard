import os
import platform

if platform.system() == "Windows":
    os.system("color")
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass


def red(text):
    return f"\033[91m{text}\033[0m"


def yellow(text):
    return f"\033[93m{text}\033[0m"


def green(text):
    return f"\033[92m{text}\033[0m"


def cyan(text):
    return f"\033[96m{text}\033[0m"
