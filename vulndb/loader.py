"""Загрузка двух JSON-фидов в базу данных.

Фид версий (versions.json):          vendor, product, version
Фид уязвимостей (vulnerabilities.json):
    vendor, product, KLA_id, description, publish_date,
    start_vuln_version, fixed_version

Что делает загрузчик
--------------------
1. Читает и проверяет оба файла (поля, типы, формат версий).
2. Раскладывает данные по таблицам схемы: вендор и продукт создаются один раз,
   даже если встречаются в обоих фидах; описание и дата бюллетеня хранятся
   в ``advisories`` один раз, а каждая строка фида уязвимостей становится
   диапазоном в ``vuln_ranges``.
3. Ключи сортировки версий всегда считает ``versioning.make_key``.
4. Всё выполняется в одной транзакции. ``load_files`` строит базу во временном
   файле и подменяет им целевой только при успехе, поэтому неудачная загрузка
   никогда не оставляет наполовину заполненную или повреждённую базу.
5. Перед подменой собранная база проходит проверки целостности (validate.py);
   при ошибках загрузка отменяется. Предупреждения и замечания проверок
   выводит отдельная команда ``python -m vulndb.validate``.

Запуск (без аргументов берутся файлы из data/ и база vulns.db):

    python -m vulndb.loader
    python -m vulndb.loader --db my.db --versions a.json --vulns b.json
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .console import make_output_safe
from .db import connect, create_schema
from .paths import DEFAULT_DB, DEFAULT_VERSIONS, DEFAULT_VULNS, PROJECT_ROOT  # noqa: F401 (реэкспорт)
from .validate import ERROR, validate
from .versioning import InvalidVersionError, make_key


VERSION_FIELDS = ("vendor", "product", "version")
VULN_FIELDS = (
    "vendor", "product", "KLA_id", "description",
    "publish_date", "start_vuln_version", "fixed_version",
)

VERSIONS_LABEL = "фид версий"
VULNS_LABEL = "фид уязвимостей"


class LoadError(Exception):
    """Данные нельзя загрузить; сообщение объясняет, где и почему."""


@dataclass
class LoadReport:
    """Итог загрузки: сколько строк в каждой таблице и предупреждения."""

    vendors: int = 0
    products: int = 0
    versions: int = 0
    advisories: int = 0
    ranges: int = 0
    warnings: list[str] = field(default_factory=list)

    def lines(self) -> list[str]:
        return [
            "Загружено:",
            f"  вендоров     {self.vendors:5d}",
            f"  продуктов    {self.products:5d}",
            f"  версий       {self.versions:5d}",
            f"  бюллетеней   {self.advisories:5d}",
            f"  диапазонов   {self.ranges:5d}",
        ]


# ---------------------------------------------------------------- чтение JSON

def read_json(path: str | Path) -> list[dict]:
    """Читает JSON-файл, в котором ожидается массив объектов."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8-sig")  # -sig: терпим BOM
    except FileNotFoundError:
        raise LoadError(f"файл не найден: {path}") from None
    except UnicodeDecodeError as exc:
        raise LoadError(f"{path.name}: файл не в кодировке UTF-8 ({exc.reason})") from None
    except OSError as exc:
        raise LoadError(f"не удалось прочитать {path}: {exc.strerror or exc}") from None

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise LoadError(
            f"{path.name}: некорректный JSON (строка {exc.lineno}, столбец {exc.colno}): {exc.msg}"
        ) from None

    if not isinstance(data, list):
        raise LoadError(f"{path.name}: ожидался JSON-массив записей")
    for index, item in enumerate(data, start=1):
        if not isinstance(item, dict):
            raise LoadError(f"{path.name}, запись №{index}: ожидался JSON-объект")
    return data


# ---------------------------------------------------- проверка отдельных записей

def _clean(record: dict, fields: tuple[str, ...], label: str, index: int) -> dict[str, str]:
    """Берёт нужные поля записи: все должны быть непустыми строками."""
    cleaned: dict[str, str] = {}
    for name in fields:
        if name not in record:
            raise LoadError(f"{label}, запись №{index}: нет поля '{name}'")
        value = record[name]
        if not isinstance(value, str):
            raise LoadError(
                f"{label}, запись №{index}: поле '{name}' должно быть строкой, "
                f"получено {type(value).__name__}"
            )
        value = value.strip()
        if not value:
            raise LoadError(f"{label}, запись №{index}: поле '{name}' пустое")
        cleaned[name] = value
    return cleaned


def _key(text: str, name: str, label: str, index: int) -> str:
    try:
        return make_key(text)
    except InvalidVersionError as exc:
        raise LoadError(f"{label}, запись №{index}: поле '{name}': {exc}") from None


# ------------------------------------------------------------ каталог продуктов

class _Catalog:
    """Создаёт вендоров и продукты по одному разу, сколько бы раз они ни встретились.

    Имена сравниваются без учёта регистра (как в схеме для продуктов);
    остаётся написание из первой встреченной записи.
    """

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        self._vendors: dict[str, int] = {}
        self._products: dict[tuple[str, str], int] = {}

    def product_id(self, vendor: str, product: str) -> int:
        vendor_key = vendor.casefold()
        vendor_id = self._vendors.get(vendor_key)
        if vendor_id is None:
            vendor_id = self._conn.execute(
                "INSERT INTO vendors(name) VALUES (?)", (vendor,)
            ).lastrowid
            self._vendors[vendor_key] = vendor_id

        product_key = (vendor_key, product.casefold())
        product_id = self._products.get(product_key)
        if product_id is None:
            product_id = self._conn.execute(
                "INSERT INTO products(vendor_id, name) VALUES (?, ?)", (vendor_id, product)
            ).lastrowid
            self._products[product_key] = product_id
        return product_id


# ------------------------------------------------------------------ загрузка

def load_data(
    conn: sqlite3.Connection,
    versions: list[dict],
    vulns: list[dict],
) -> LoadReport:
    """Загружает записи двух фидов в пустую базу со схемой (одна транзакция).

    При любой ошибке транзакция откатывается и бросается LoadError.
    """
    if conn.execute("SELECT EXISTS (SELECT 1 FROM vendors)").fetchone()[0]:
        raise LoadError("база данных не пуста: загрузка выполняется только в пустую базу")

    report = LoadReport()

    with conn:  # коммит при успехе, откат при исключении
        catalog = _Catalog(conn)

        # --- фид версий ---------------------------------------------------
        seen_versions: set[tuple[int, str]] = set()
        duplicate_versions = 0
        for index, raw in enumerate(versions, start=1):
            rec = _clean(raw, VERSION_FIELDS, VERSIONS_LABEL, index)
            key = _key(rec["version"], "version", VERSIONS_LABEL, index)
            product_id = catalog.product_id(rec["vendor"], rec["product"])

            if (product_id, rec["version"]) in seen_versions:
                duplicate_versions += 1
                continue
            seen_versions.add((product_id, rec["version"]))
            conn.execute(
                "INSERT INTO versions(product_id, version, version_key) VALUES (?, ?, ?)",
                (product_id, rec["version"], key),
            )
        if duplicate_versions:
            report.warnings.append(
                f"{VERSIONS_LABEL}: пропущено повторяющихся строк: {duplicate_versions}"
            )

        # --- фид уязвимостей ---------------------------------------------
        advisories: dict[str, tuple[str, str]] = {}
        seen_ranges: set[tuple[str, int, str, str]] = set()
        duplicate_ranges = 0
        for index, raw in enumerate(vulns, start=1):
            rec = _clean(raw, VULN_FIELDS, VULNS_LABEL, index)
            kla = rec["KLA_id"]
            where = f"{VULNS_LABEL}, запись №{index} ({kla})"

            start_key = _key(rec["start_vuln_version"], "start_vuln_version", VULNS_LABEL, index)
            fixed_key = _key(rec["fixed_version"], "fixed_version", VULNS_LABEL, index)
            if start_key > fixed_key:
                raise LoadError(
                    f"{where}: первая уязвимая версия {rec['start_vuln_version']} "
                    f"больше первой исправленной {rec['fixed_version']}"
                )

            # Бюллетень: описание и дата общие для всех его строк.
            info = (rec["description"], rec["publish_date"])
            known = advisories.get(kla)
            if known is None:
                try:
                    conn.execute(
                        "INSERT INTO advisories(kla_id, description, publish_date) VALUES (?, ?, ?)",
                        (kla, *info),
                    )
                except sqlite3.IntegrityError as exc:
                    raise LoadError(
                        f"{where}: запись отклонена базой данных ({exc}). "
                        "Ожидаются KLA_id вида KLA12345 и publish_date вида ГГГГ-ММ-ДД"
                    ) from None
                advisories[kla] = info
            elif known != info:
                raise LoadError(
                    f"{where}: описание или дата отличаются от первой записи с этим "
                    f"идентификатором (было {known!r}, стало {info!r})"
                )

            product_id = catalog.product_id(rec["vendor"], rec["product"])

            signature = (kla, product_id, start_key, fixed_key)
            if signature in seen_ranges:
                duplicate_ranges += 1
                continue
            seen_ranges.add(signature)

            if start_key == fixed_key:
                report.warnings.append(
                    f"{kla} ({rec['product']}): диапазон {rec['start_vuln_version']} → "
                    f"{rec['fixed_version']} пуст (версии равны), ни одна версия под него не попадает"
                )

            conn.execute(
                "INSERT INTO vuln_ranges(kla_id, product_id, start_version, start_key, "
                "fixed_version, fixed_key) VALUES (?, ?, ?, ?, ?, ?)",
                (kla, product_id, rec["start_vuln_version"], start_key,
                 rec["fixed_version"], fixed_key),
            )
        if duplicate_ranges:
            report.warnings.append(
                f"{VULNS_LABEL}: пропущено повторяющихся строк: {duplicate_ranges}"
            )

        # --- итог по таблицам ----------------------------------------------
        def count(table: str) -> int:
            return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]

        report.vendors = count("vendors")
        report.products = count("products")
        report.versions = count("versions")
        report.advisories = count("advisories")
        report.ranges = count("vuln_ranges")

    return report


def load_files(
    db_path: str | Path = DEFAULT_DB,
    versions_path: str | Path = DEFAULT_VERSIONS,
    vulns_path: str | Path = DEFAULT_VULNS,
) -> LoadReport:
    """Создаёт базу заново и загружает в неё оба файла.

    Существующая база по ``db_path`` заменяется только после полностью
    успешной загрузки; при ошибке она остаётся нетронутой.
    """
    versions = read_json(versions_path)
    vulns = read_json(vulns_path)

    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = db_path.with_name(db_path.name + ".tmp")
    tmp_path.unlink(missing_ok=True)

    conn = connect(tmp_path)
    try:
        create_schema(conn)
        report = load_data(conn, versions, vulns)
        check = validate(conn)
        if not check.ok:
            details = "\n".join(
                f"  - {result.title}: {problem}"
                for result in check.failed(ERROR)
                for problem in result.problems[:5]
            )
            raise LoadError("проверка целостности собранной базы не пройдена:\n" + details)
    except BaseException:
        conn.close()
        tmp_path.unlink(missing_ok=True)
        raise
    conn.close()
    os.replace(tmp_path, db_path)  # атомарная подмена
    return report


# --------------------------------------------------------------------- запуск

def run(db: Path, versions: Path, vulns: Path) -> int:
    """Загружает данные и печатает итог. Возвращает код выхода: 0 или 1."""
    try:
        report = load_files(db, versions, vulns)
    except (LoadError, OSError, sqlite3.Error) as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1

    for warning in report.warnings:
        print(f"Предупреждение: {warning}", file=sys.stderr)
    print(f"База данных: {db}")
    print("\n".join(report.lines()))
    return 0


def main(argv: list[str] | None = None) -> int:
    make_output_safe()
    parser = argparse.ArgumentParser(
        prog="python -m vulndb.loader",
        description="Создать базу данных и загрузить в неё оба JSON-фида.",
    )
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, help="файл базы (по умолчанию vulns.db)")
    parser.add_argument("--versions", type=Path, default=DEFAULT_VERSIONS, help="фид версий")
    parser.add_argument("--vulns", type=Path, default=DEFAULT_VULNS, help="фид уязвимостей")
    args = parser.parse_args(argv)
    return run(args.db, args.versions, args.vulns)


if __name__ == "__main__":
    sys.exit(main())
