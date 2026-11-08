"""Консольный интерфейс.

    python vulndb.py load                          создать базу и загрузить данные
    python vulndb.py safe  "Apache Tomcat"         версия без известных уязвимостей
    python vulndb.py safe  "Apache Tomcat" --all   все такие версии
    python vulndb.py check "Apache Tomcat" 9.0.50  уязвимости конкретной версии
    python vulndb.py products                      список продуктов в базе
    python vulndb.py validate                      проверить целостность базы

Названия продуктов можно писать и без кавычек: ``safe Apache Tomcat``.

Коды выхода:
    0  успех
    1  продукт не найден (или название неоднозначно), база не найдена или не читается,
       загрузка не удалась
    2  неверный формат версии или неверные аргументы командной строки
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from pathlib import Path

from .console import make_output_safe
from .db import connect_readonly
from .loader import run as run_load
from .paths import DEFAULT_DB, DEFAULT_VERSIONS, DEFAULT_VULNS
from .queries import (
    QueryError,
    SafeVersions,
    VulnerabilityReport,
    list_products,
    safe_versions,
    vulnerabilities_for,
)
from .validate import run as run_validate
from .versioning import InvalidVersionError, make_key

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2


# ------------------------------------------------------------------ оформление
# Функции форматирования возвращают список строк: так их удобно проверять тестами.
# В тексте только кириллица, латиница и простые знаки: он одинаково выводится
# в любой консоли.

def format_safe(result: SafeVersions, show_all: bool = False) -> list[str]:
    product = result.product
    lines = [f"Продукт: {product.name} (вендор: {product.vendor})"]

    if result.total == 0:
        lines.append("В базе нет версий этого продукта.")
        return lines

    if not result.safe:
        lines.append(f"Версий без известных уязвимостей в базе нет (проверено версий: {result.total}).")
        lines.append(f"Самая новая известная версия: {result.latest_known} (уязвима).")
        if result.upgrade_target:
            lines.append(
                f"Ближайшая версия без известных уязвимостей: {result.upgrade_target} "
                "(в базе такой версии нет)."
            )
        return lines

    if show_all:
        lines.append(f"Версии без известных уязвимостей ({len(result.safe)} из {result.total}):")
        lines.extend(f"  {version}" for version in result.safe)
    else:
        lines.append(f"Версия без известных уязвимостей: {result.latest_safe}")
        if len(result.safe) > 1:
            lines.append(
                f"(всего таких версий: {len(result.safe)} из {result.total}; "
                "полный список: добавьте --all)"
            )

    if result.latest_known != result.latest_safe:
        lines.append(
            f"Внимание: в базе есть более новые версии (до {result.latest_known}), но они уязвимы."
        )
    return lines


def format_check(report: VulnerabilityReport) -> list[str]:
    product = report.product
    lines = [
        f"Продукт: {product.name} (вендор: {product.vendor})",
        f"Версия: {report.version}",
    ]
    if not report.in_catalog:
        lines.append(
            "Примечание: такой версии нет в справочнике версий; "
            "проверка выполнена по диапазонам уязвимостей."
        )

    if not report.is_vulnerable:
        lines.append("Известных уязвимостей не найдено.")
        return lines

    lines.append(f"Найдено уязвимостей: {len(report.vulnerabilities)}")
    for number, vuln in enumerate(report.vulnerabilities, start=1):
        first_vulnerable = min((r.start for r in vuln.ranges), key=make_key)
        lines.append("")
        lines.append(f"{number}. {vuln.kla_id} ({vuln.publish_date})")
        lines.append(f"   {vuln.description}")
        lines.append(f"   Первая уязвимая версия: {first_vulnerable}")
        lines.append(f"   Исправлено в: {', '.join(vuln.fixed_versions)}")

    lines.append("")
    lines.append(f"Ближайшая версия без известных уязвимостей: {report.upgrade_target}")
    return lines


# --------------------------------------------------------------------- команды

def _cmd_load(args: argparse.Namespace) -> int:
    return run_load(args.db, args.versions, args.vulns)


def _cmd_validate(args: argparse.Namespace) -> int:
    return run_validate(args.db)


def _cmd_products(args: argparse.Namespace) -> int:
    conn = connect_readonly(args.db)
    try:
        products = list_products(conn)
    finally:
        conn.close()

    if not products:
        print("В базе нет продуктов.")
        return EXIT_OK
    width = max(len(p.name) for p in products)
    print(f"{'Продукт'.ljust(width)}  Вендор")
    for p in products:
        print(f"{p.name.ljust(width)}  {p.vendor}")
    print(f"\nВсего продуктов: {len(products)}")
    return EXIT_OK


def _cmd_safe(args: argparse.Namespace) -> int:
    conn = connect_readonly(args.db)
    try:
        result = safe_versions(conn, " ".join(args.product), args.vendor)
    finally:
        conn.close()
    print("\n".join(format_safe(result, args.all)))
    return EXIT_OK


def _cmd_check(args: argparse.Namespace) -> int:
    if len(args.words) < 2:
        args.parser.error("нужны название продукта и версия, например: check \"Apache Tomcat\" 9.0.50")
    *name_words, version = args.words   # версия всегда последняя
    conn = connect_readonly(args.db)
    try:
        report = vulnerabilities_for(conn, " ".join(name_words), version, args.vendor)
    finally:
        conn.close()
    print("\n".join(format_check(report)))
    return EXIT_OK


# ---------------------------------------------------------------- разбор команд

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python vulndb.py",
        description="Поиск уязвимостей в программных продуктах по базе данных.",
        epilog=(
            "примеры:\n"
            "  python vulndb.py load\n"
            "  python vulndb.py safe \"Apache Tomcat\"\n"
            "  python vulndb.py check \"Apache Tomcat\" 9.0.50\n"
            "\n"
            "Справка по команде: python vulndb.py <команда> --help"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    commands = parser.add_subparsers(dest="command", metavar="команда", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--db", type=Path, default=DEFAULT_DB,
                        help="файл базы данных (по умолчанию vulns.db рядом с программой)")

    vendor_help = "вендор (нужен, только если название продукта есть у нескольких вендоров)"

    load = commands.add_parser(
        "load", parents=[common], help="создать базу и загрузить в неё данные",
        description="Создать базу данных заново и загрузить в неё оба JSON-фида.")
    load.add_argument("--versions", type=Path, default=DEFAULT_VERSIONS, help="фид версий (JSON)")
    load.add_argument("--vulns", type=Path, default=DEFAULT_VULNS, help="фид уязвимостей (JSON)")
    load.set_defaults(handler=_cmd_load)

    safe = commands.add_parser(
        "safe", parents=[common], help="версия продукта без известных уязвимостей",
        description="По названию продукта вывести версию без известных уязвимостей "
                    "(самую новую из безопасных).")
    safe.add_argument("product", nargs="+", metavar="ПРОДУКТ",
                      help="название продукта, например \"Apache Tomcat\"")
    safe.add_argument("--vendor", help=vendor_help)
    safe.add_argument("-a", "--all", action="store_true", help="показать все безопасные версии")
    safe.set_defaults(handler=_cmd_safe)

    check = commands.add_parser(
        "check", parents=[common], help="уязвимости конкретной версии продукта",
        description="По названию продукта и версии вывести информацию об уязвимостях.")
    check.add_argument("words", nargs="+", metavar="ПРОДУКТ ВЕРСИЯ",
                       help="название продукта и версия, например: \"Apache Tomcat\" 9.0.50")
    check.add_argument("--vendor", help=vendor_help)
    check.set_defaults(handler=_cmd_check, parser=check)

    products = commands.add_parser(
        "products", parents=[common], help="список продуктов в базе",
        description="Вывести продукты, которые есть в базе, вместе с вендорами.")
    products.set_defaults(handler=_cmd_products)

    validate = commands.add_parser(
        "validate", parents=[common], help="проверить целостность базы",
        description="Проверить целостность базы данных (база не изменяется).")
    validate.set_defaults(handler=_cmd_validate)

    return parser


def _fail(message: object, code: int) -> int:
    print(f"Ошибка: {message}", file=sys.stderr)
    return code


def main(argv: list[str] | None = None) -> int:
    make_output_safe()
    args = build_parser().parse_args(argv)   # при неверных аргументах argparse сам выходит с кодом 2
    try:
        return args.handler(args)
    except InvalidVersionError as exc:
        return _fail(exc, EXIT_USAGE)
    except QueryError as exc:
        return _fail(exc, EXIT_FAILURE)
    except FileNotFoundError as exc:
        return _fail(f"{exc}. Сначала создайте базу: python vulndb.py load", EXIT_FAILURE)
    except sqlite3.Error as exc:
        return _fail(
            f"не удалось прочитать базу данных ({exc}). Пересоздайте её: python vulndb.py load",
            EXIT_FAILURE,
        )
    except KeyboardInterrupt:
        return _fail("прервано пользователем", 130)
    except BrokenPipeError:
        # Потребитель вывода закрылся раньше времени (например, `... | head`).
        # Перенаправляем stdout в никуда, чтобы Python не печатал трассировку при выходе.
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except (OSError, ValueError):   # у подменённого потока (тесты) нет файлового дескриптора
            pass
        return EXIT_FAILURE
