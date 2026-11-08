"""Мелочи для консольного вывода."""

from __future__ import annotations

import sys


def make_output_safe() -> None:
    """Не даёт программе упасть, если в тексте есть символ, которого нет в кодировке консоли.

    Например, при выводе в файл на Windows используется кодировка cp1251, где нет
    стрелки «→». Вместо исключения UnicodeEncodeError такой символ печатается как «?».
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)  # у StringIO его нет
        if reconfigure is not None:
            try:
                reconfigure(errors="replace")
            except (ValueError, OSError):
                pass
