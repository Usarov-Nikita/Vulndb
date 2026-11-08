#!/usr/bin/env python3
"""Точка входа консольного инструмента: python vulndb.py <команда> ...

Справка: python vulndb.py --help
"""

import sys

# Рядом лежат и этот файл vulndb.py, и папка-пакет vulndb/. Python при импорте
# сначала находит папку-пакет, поэтому имя здесь означает именно пакет.
from vulndb.cli import main

if __name__ == "__main__":
    sys.exit(main())
