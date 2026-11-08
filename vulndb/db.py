"""Подключение к SQLite и создание схемы."""

from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA_PATH = Path(__file__).with_name("schema.sql")

# Должна совпадать с PRAGMA user_version в schema.sql (это проверяет тест).
SCHEMA_VERSION = 1


def connect(path: str | Path = ":memory:") -> sqlite3.Connection:
    """Открывает соединение с включёнными внешними ключами.

    В SQLite проверка внешних ключей по умолчанию выключена и включается
    отдельно для каждого соединения, поэтому все подключения к базе
    должны идти через эту функцию (или через connect_readonly).
    """
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def connect_readonly(path: str | Path) -> sqlite3.Connection:
    """Открывает существующую базу только для чтения.

    В отличие от connect(), не создаёт файл, если его нет, и не позволяет
    ничего изменить: так безопасно проверять и опрашивать чужую базу.
    Бросает FileNotFoundError, если файла нет.
    """
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"файл базы данных не найден: {path}")
    # as_uri() корректно кодирует пробелы, кириллицу и спецсимволы в пути
    conn = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def create_schema(conn: sqlite3.Connection) -> None:
    """Создаёт таблицы и индексы из schema.sql (в пустой базе)."""
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
