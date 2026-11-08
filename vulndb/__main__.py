"""Запуск как модуля: python -m vulndb <команда> ... (то же, что python vulndb.py)."""

import sys

from .cli import main

sys.exit(main())
