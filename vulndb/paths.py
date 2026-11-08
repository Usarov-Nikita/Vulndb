"""Расположение проекта и файлов по умолчанию."""

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB = PROJECT_ROOT / "vulns.db"
DEFAULT_VERSIONS = PROJECT_ROOT / "data" / "versions.json"
DEFAULT_VULNS = PROJECT_ROOT / "data" / "vulnerabilities.json"
