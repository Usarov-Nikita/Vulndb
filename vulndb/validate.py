"""Проверки целостности готовой базы данных.

Загрузчик отклоняет заведомо плохие входные данные, а этот модуль проверяет
итог: то, что лежит в самой базе. Так можно убедиться в её исправности в любой
момент, в том числе для базы, собранной другим способом.

Каждая проверка -- это утверждение, которое должно выполняться. Если оно
нарушено, в отчёт попадает список отклонений. Важность проверки определяет,
что с ними делать:

    ОШИБКА          база повреждена или противоречива, пользоваться ею нельзя
    ПРЕДУПРЕЖДЕНИЕ  данные подозрительны, но база работоспособна
    ЗАМЕЧАНИЕ       наблюдение о данных, которое полезно знать

Как проверки связаны с двумя фидами: после загрузки они склеены в одну базу,
поэтому «продукт есть в обоих фидах» проверяется как «у продукта есть и версии
(фид версий), и правила уязвимостей (фид уязвимостей)».

Запуск:

    python -m vulndb.validate
    python -m vulndb.validate --db other.db

Код возврата 0, если ошибок нет (предупреждения и замечания его не меняют),
и 1, если найдены ошибки или базу не удалось открыть.
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .console import make_output_safe
from .db import SCHEMA_VERSION, connect_readonly
from .paths import DEFAULT_DB
from .versioning import InvalidVersionError, make_key

ERROR = "error"
WARNING = "warning"
INFO = "info"

_LABELS = {ERROR: "ОШИБКА", WARNING: "ПРЕДУПРЕЖДЕНИЕ", INFO: "ЗАМЕЧАНИЕ"}

REQUIRED_TABLES = ("vendors", "products", "versions", "advisories", "vuln_ranges")


@dataclass
class CheckResult:
    """Результат одной проверки: пустой список problems означает «пройдена»."""

    id: str
    title: str
    severity: str
    problems: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.problems


@dataclass
class ValidationReport:
    results: list[CheckResult] = field(default_factory=list)

    def failed(self, severity: str | None = None) -> list[CheckResult]:
        """Непройденные проверки (при необходимости -- только заданной важности)."""
        return [
            r for r in self.results
            if not r.passed and (severity is None or r.severity == severity)
        ]

    @property
    def ok(self) -> bool:
        """True, если нет ни одной ошибки (предупреждения и замечания допустимы)."""
        return not self.failed(ERROR)

    def lines(self, max_details: int = 8) -> list[str]:
        out: list[str] = []
        for result in self.results:
            if result.passed:
                out.append(f"[ OK ] {result.title}")
                continue
            out.append(
                f"[{_LABELS[result.severity]}] {result.title} — отклонений: {len(result.problems)}"
            )
            for problem in result.problems[:max_details]:
                out.append(f"    {problem}")
            hidden = len(result.problems) - max_details
            if hidden > 0:
                out.append(f"    … и ещё {hidden}")

        errors = len(self.failed(ERROR))
        warnings = len(self.failed(WARNING))
        notes = len(self.failed(INFO))
        out.append("")
        if errors:
            out.append(
                f"Итог: найдены ошибки ({errors}); предупреждений {warnings}, замечаний {notes}. "
                "Пользоваться базой нельзя."
            )
        else:
            out.append(
                f"Итог: ошибок нет; предупреждений {warnings}, замечаний {notes}. "
                "База пригодна к работе."
            )
        return out


# ------------------------------------------------------------------ проверки
# Каждая функция возвращает список отклонений (пустой -- всё хорошо).
# Строки результата читаются по индексам, поэтому row_factory не важен.

def _check_structure(conn: sqlite3.Connection) -> list[str]:
    try:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        version = conn.execute("PRAGMA user_version").fetchone()[0]
    except sqlite3.DatabaseError as exc:
        return [f"файл не читается как база SQLite: {exc}"]
    problems = [f"нет таблицы {name}" for name in REQUIRED_TABLES if name not in tables]
    if version != SCHEMA_VERSION:
        problems.append(f"версия схемы {version}, ожидалась {SCHEMA_VERSION}")
    return problems


def _check_sqlite_integrity(conn: sqlite3.Connection) -> list[str]:
    return [r[0] for r in conn.execute("PRAGMA integrity_check") if r[0] != "ok"]


def _check_foreign_keys(conn: sqlite3.Connection) -> list[str]:
    return [
        f"таблица {r[0]}, строка rowid={r[1]}: нет родительской записи в {r[2]}"
        for r in conn.execute("PRAGMA foreign_key_check")
    ]


def _key_problem(text: str, stored: str) -> str | None:
    """Сверяет сохранённый ключ с тем, что даёт make_key для текста версии."""
    try:
        expected = make_key(text)
    except InvalidVersionError:
        return "текст не является корректной версией"
    return None if stored == expected else "ключ не соответствует версии"


def _check_version_keys(conn: sqlite3.Connection) -> list[str]:
    problems = []
    for product, version, stored in conn.execute(
        "SELECT p.name, v.version, v.version_key FROM versions v "
        "JOIN products p ON p.id = v.product_id ORDER BY p.name, v.id"
    ):
        why = _key_problem(version, stored)
        if why:
            problems.append(f"{product} {version}: {why}")
    return problems


def _check_range_keys(conn: sqlite3.Connection) -> list[str]:
    problems = []
    for kla, product, start, start_key, fixed, fixed_key in conn.execute(
        "SELECT r.kla_id, p.name, r.start_version, r.start_key, r.fixed_version, r.fixed_key "
        "FROM vuln_ranges r JOIN products p ON p.id = r.product_id ORDER BY r.id"
    ):
        label = f"{kla} {product} ({start} → {fixed})"
        for part, text, stored in (("начало", start, start_key), ("конец", fixed, fixed_key)):
            why = _key_problem(text, stored)
            if why:
                problems.append(f"{label}: {part}: {why}")
        if start_key > fixed_key:
            problems.append(f"{label}: начало диапазона больше конца")
    return problems


def _query(conn: sqlite3.Connection, sql: str, fmt: Callable[..., str]) -> list[str]:
    return [fmt(*row) for row in conn.execute(sql)]


def _check_products_have_versions(conn: sqlite3.Connection) -> list[str]:
    return _query(conn, """
        SELECT p.name FROM products p
        WHERE EXISTS (SELECT 1 FROM vuln_ranges r WHERE r.product_id = p.id)
          AND NOT EXISTS (SELECT 1 FROM versions v WHERE v.product_id = p.id)
        ORDER BY p.name
    """, lambda name: f"{name}: есть правила уязвимостей, но нет ни одной версии")


def _check_advisories_have_ranges(conn: sqlite3.Connection) -> list[str]:
    return _query(conn, """
        SELECT a.kla_id FROM advisories a
        WHERE NOT EXISTS (SELECT 1 FROM vuln_ranges r WHERE r.kla_id = a.kla_id)
        ORDER BY a.kla_id
    """, lambda kla: f"{kla}: бюллетень без диапазонов")


def _check_vendors_have_products(conn: sqlite3.Connection) -> list[str]:
    return _query(conn, """
        SELECT x.name FROM vendors x
        WHERE NOT EXISTS (SELECT 1 FROM products p WHERE p.vendor_id = x.id)
        ORDER BY x.name
    """, lambda name: f"{name}: вендор без продуктов")


def _check_no_equivalent_versions(conn: sqlite3.Connection) -> list[str]:
    return _query(conn, """
        SELECT p.name, group_concat(v.version, ' = ')
        FROM versions v JOIN products p ON p.id = v.product_id
        GROUP BY v.product_id, v.version_key HAVING COUNT(*) > 1
        ORDER BY p.name
    """, lambda name, versions: f"{name}: {versions}")


def _check_no_empty_ranges(conn: sqlite3.Connection) -> list[str]:
    return _query(conn, """
        SELECT r.kla_id, p.name, r.start_version, r.fixed_version
        FROM vuln_ranges r JOIN products p ON p.id = r.product_id
        WHERE r.start_key = r.fixed_key
        ORDER BY r.kla_id
    """, lambda kla, product, start, fixed: f"{kla} {product}: {start} → {fixed}")


def _check_fixed_in_catalog(conn: sqlite3.Connection) -> list[str]:
    # Сравнение по значению (по ключу), а не по тексту: 128.3 и 128.3.0 -- одна версия.
    return _query(conn, """
        SELECT p.name, r.fixed_version, group_concat(DISTINCT r.kla_id)
        FROM vuln_ranges r JOIN products p ON p.id = r.product_id
        WHERE NOT EXISTS (SELECT 1 FROM versions v
                          WHERE v.product_id = r.product_id AND v.version_key = r.fixed_key)
        GROUP BY r.product_id, r.fixed_key
        ORDER BY p.name, r.fixed_key
    """, lambda name, fixed, klas: f"{name} {fixed}: нет в справочнике версий (бюллетени: {klas})")


def _check_ranges_match_versions(conn: sqlite3.Connection) -> list[str]:
    # Пустые диапазоны (start = fixed) отчитываются отдельной проверкой.
    return _query(conn, """
        SELECT r.kla_id, p.name, r.start_version, r.fixed_version
        FROM vuln_ranges r JOIN products p ON p.id = r.product_id
        WHERE r.start_key < r.fixed_key
          AND NOT EXISTS (SELECT 1 FROM versions v
                          WHERE v.product_id = r.product_id
                            AND r.start_key <= v.version_key AND v.version_key < r.fixed_key)
        ORDER BY r.kla_id, p.name
    """, lambda kla, product, start, fixed: f"{kla} {product}: {start} → {fixed}")


def _check_products_have_ranges(conn: sqlite3.Connection) -> list[str]:
    return _query(conn, """
        SELECT p.name FROM products p
        WHERE EXISTS (SELECT 1 FROM versions v WHERE v.product_id = p.id)
          AND NOT EXISTS (SELECT 1 FROM vuln_ranges r WHERE r.product_id = p.id)
        ORDER BY p.name
    """, lambda name: f"{name}: правил нет, все версии считаются безопасными")


def _check_products_have_safe_version(conn: sqlite3.Connection) -> list[str]:
    return _query(conn, """
        SELECT p.name FROM products p
        WHERE EXISTS (SELECT 1 FROM versions v WHERE v.product_id = p.id)
          AND NOT EXISTS (
              SELECT 1 FROM versions v
              WHERE v.product_id = p.id
                AND NOT EXISTS (SELECT 1 FROM vuln_ranges r
                                WHERE r.product_id = v.product_id
                                  AND r.start_key <= v.version_key
                                  AND v.version_key < r.fixed_key))
        ORDER BY p.name
    """, lambda name: f"{name}: все известные версии уязвимы")


_STRUCTURE_TITLE = "Структура базы соответствует схеме (таблицы, версия схемы)"

# (идентификатор, формулировка утверждения, важность, функция проверки)
_CHECKS: list[tuple[str, str, str, Callable[[sqlite3.Connection], list[str]]]] = [
    ("sqlite_integrity", "Файл базы SQLite цел (integrity_check)", ERROR,
     _check_sqlite_integrity),
    ("foreign_keys", "Внешние ключи без нарушений", ERROR,
     _check_foreign_keys),
    ("version_keys", "Ключи версий соответствуют их тексту", ERROR,
     _check_version_keys),
    ("range_keys", "Ключи диапазонов соответствуют тексту, начало не больше конца", ERROR,
     _check_range_keys),
    ("products_have_versions", "У каждого продукта с правилами уязвимостей есть версии в справочнике",
     WARNING, _check_products_have_versions),
    ("advisories_have_ranges", "У каждого бюллетеня есть хотя бы один диапазон", WARNING,
     _check_advisories_have_ranges),
    ("vendors_have_products", "У каждого вендора есть продукты", WARNING,
     _check_vendors_have_products),
    ("no_equivalent_versions", "В продукте нет версий, равных по значению (например, 1.0 и 1.0.0)",
     WARNING, _check_no_equivalent_versions),
    ("no_empty_ranges", "Нет пустых диапазонов (начало равно концу)", WARNING,
     _check_no_empty_ranges),
    ("fixed_in_catalog", "Исправленные версии из правил есть в справочнике версий", INFO,
     _check_fixed_in_catalog),
    ("ranges_match_versions", "Каждое правило охватывает хотя бы одну известную версию", INFO,
     _check_ranges_match_versions),
    ("products_have_ranges", "У каждого продукта есть правила уязвимостей", INFO,
     _check_products_have_ranges),
    ("products_have_safe_version", "У каждого продукта есть хотя бы одна безопасная версия", INFO,
     _check_products_have_safe_version),
]


def validate(conn: sqlite3.Connection) -> ValidationReport:
    """Выполняет все проверки и возвращает отчёт.

    Если структура базы не соответствует схеме, остальные проверки не имеют
    смысла (нет нужных таблиц и столбцов), поэтому отчёт состоит из одной ошибки.
    """
    report = ValidationReport()
    structure = CheckResult("structure", _STRUCTURE_TITLE, ERROR, _check_structure(conn))
    report.results.append(structure)
    if structure.problems:
        return report

    for check_id, title, severity, check in _CHECKS:
        try:
            problems = check(conn)
        except sqlite3.DatabaseError as exc:  # например, повреждённые страницы файла
            problems = [f"проверка не выполнена: {exc}"]
        report.results.append(CheckResult(check_id, title, severity, problems))
    return report


# --------------------------------------------------------------------- запуск

def run(db: Path) -> int:
    """Проверяет базу и печатает отчёт. Код выхода: 0 -- ошибок нет, 1 -- есть ошибки."""
    try:
        conn = connect_readonly(db)
    except (FileNotFoundError, sqlite3.Error) as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1
    try:
        report = validate(conn)
    finally:
        conn.close()

    print(f"Проверка базы данных: {db}\n")
    print("\n".join(report.lines()))
    return 0 if report.ok else 1


def main(argv: list[str] | None = None) -> int:
    make_output_safe()
    parser = argparse.ArgumentParser(
        prog="python -m vulndb.validate",
        description="Проверить целостность базы данных (база не изменяется).",
    )
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, help="файл базы (по умолчанию vulns.db)")
    args = parser.parse_args(argv)
    return run(args.db)


if __name__ == "__main__":
    sys.exit(main())
