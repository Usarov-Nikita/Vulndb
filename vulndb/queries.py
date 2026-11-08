"""Запросы к базе: безопасные версии продукта и уязвимости конкретной версии.

Главное утверждение (то же, что проверялось в SQL на шаге 2)
-------------------------------------------------------------
Версия v продукта P уязвима по правилу r, если   start(r) <= v < fixed(r).
Версия безопасна, если по P нет ни одного правила, под которое она попадает.

Правила берутся буквально, как они записаны в фиде. Если у бюллетеня несколько
строк с началом ``0`` (по одной на ветку продукта, как у PostgreSQL), то их
объединение закрывает всё от нуля до самой большой исправленной версии.
Информацию о ветках фид не содержит, поэтому модуль её и не домысливает.

Сравнение версий идёт по ключам из versioning.make_key: версия ``128.3``
равна ``128.3.0``, а ``9.0.10`` больше ``9.0.9``.

Две функции для консольного инструмента:

    safe_versions(conn, "Apache Tomcat")
    vulnerabilities_for(conn, "Apache Tomcat", "9.0.50")

Обе только читают базу и работают с любым соединением (в том числе с
connect_readonly).
"""

from __future__ import annotations

import difflib
import sqlite3
from dataclasses import dataclass

from .versioning import make_key

# InvalidVersionError (из versioning) пробрасывается как есть: версия
# в вопросе записана неверно, и вызывающий код решает, что с этим делать.


# ------------------------------------------------------------------ ошибки

class QueryError(Exception):
    """Базовая ошибка запроса; текст сообщения можно показывать пользователю."""


class ProductNotFoundError(QueryError):
    """Продукта с таким названием нет в базе."""

    def __init__(self, name: str, suggestions: list[str] | None = None, detail: str | None = None):
        self.name = name
        self.suggestions = list(suggestions or [])
        message = detail or f"продукт '{name}' не найден"
        if self.suggestions:
            message += ". Возможно, вы имели в виду: " + "; ".join(self.suggestions)
        super().__init__(message)


class AmbiguousProductError(QueryError):
    """Одно и то же название у нескольких вендоров: нужно уточнить вендора."""

    def __init__(self, name: str, vendors: list[str]):
        self.name = name
        self.vendors = list(vendors)
        super().__init__(
            f"название '{name}' есть у нескольких вендоров ({'; '.join(self.vendors)}); "
            "укажите вендора"
        )


# --------------------------------------------------------------- результаты

@dataclass(frozen=True)
class Product:
    id: int
    vendor: str
    name: str


@dataclass(frozen=True)
class VersionRange:
    start: str   # первая уязвимая версия ("0" = с самого начала)
    fixed: str   # первая исправленная версия (сама уже не уязвима)


@dataclass(frozen=True)
class Vulnerability:
    """Один бюллетень безопасности, затрагивающий проверяемую версию.

    ``ranges`` -- все диапазоны этого бюллетеня, в которые попала версия,
    по возрастанию исправленной версии.
    """

    kla_id: str
    publish_date: str
    description: str
    ranges: tuple[VersionRange, ...]

    @property
    def fixed_versions(self) -> tuple[str, ...]:
        """Исправленные версии по возрастанию, без повторов."""
        seen: list[str] = []
        for r in self.ranges:
            if r.fixed not in seen:
                seen.append(r.fixed)
        return tuple(seen)


@dataclass(frozen=True)
class VulnerabilityReport:
    product: Product
    version: str
    in_catalog: bool                          # есть ли такая версия в справочнике
    vulnerabilities: tuple[Vulnerability, ...]  # новые бюллетени первыми
    # Наименьшая версия не ниже проверяемой, под которую не попадает ни одно
    # правило продукта (может отсутствовать в справочнике). None, если версия
    # не уязвима.
    upgrade_target: str | None

    @property
    def is_vulnerable(self) -> bool:
        return bool(self.vulnerabilities)


@dataclass(frozen=True)
class SafeVersions:
    product: Product
    total: int                      # сколько версий продукта в справочнике
    safe: tuple[str, ...]           # безопасные версии по возрастанию
    latest_known: str | None        # самая новая версия в справочнике
    # Заполняется, только если безопасных версий нет: наименьшая версия не ниже
    # самой новой известной, под которую не попадает ни одно правило.
    upgrade_target: str | None

    @property
    def latest_safe(self) -> str | None:
        return self.safe[-1] if self.safe else None


# ------------------------------------------------------------ поиск продукта

def _suggest(conn: sqlite3.Connection, name: str, limit: int = 5) -> list[str]:
    """Похожие названия: сначала содержащие запрос (или содержащиеся в нём), затем близкие по написанию."""
    names = [r[0] for r in conn.execute("SELECT DISTINCT name FROM products ORDER BY name")]
    low = name.casefold()

    contains = [n for n in names if low in n.casefold() or n.casefold() in low]

    # Опечатка обычно в одном слове ("Tomcta"), а название длинное ("Apache Tomcat"),
    # поэтому запрос сравнивается и с названием целиком, и с каждым его словом.
    def similarity(a: str, b: str) -> float:
        return difflib.SequenceMatcher(None, a, b).ratio()

    scored = []
    for candidate in names:
        candidate_low = candidate.casefold()
        score = max([similarity(low, candidate_low)]
                    + [similarity(low, word) for word in candidate_low.split()])
        if score >= 0.6:
            scored.append((-score, candidate))
    close = [candidate for _, candidate in sorted(scored)]

    result: list[str] = []
    for candidate in contains + close:
        if candidate not in result:
            result.append(candidate)
    return result[:limit]


def find_product(conn: sqlite3.Connection, name: str, vendor: str | None = None) -> Product:
    """Находит продукт по точному названию (без учёта регистра).

    Подстроки не подходят: ``VLC media player`` не находит
    ``VLC media player (MSI installer)``. Если название встречается у нескольких
    вендоров, нужно указать ``vendor``.
    """
    name = name.strip()
    if not name:
        raise QueryError("название продукта не задано")

    sql = ("SELECT p.id, v.name, p.name FROM products p "
           "JOIN vendors v ON v.id = p.vendor_id WHERE p.name = ?")
    params: list[str] = [name]
    if vendor is not None:
        sql += " AND v.name = ? COLLATE NOCASE"
        params.append(vendor.strip())
    rows = conn.execute(sql + " ORDER BY v.name", params).fetchall()

    if len(rows) == 1:
        return Product(*rows[0])
    if len(rows) > 1:
        raise AmbiguousProductError(name, [r[1] for r in rows])

    if vendor is not None:
        elsewhere = [r[0] for r in conn.execute(
            "SELECT v.name FROM products p JOIN vendors v ON v.id = p.vendor_id "
            "WHERE p.name = ? ORDER BY v.name", (name,))]
        if elsewhere:
            raise ProductNotFoundError(
                name,
                detail=f"у вендора '{vendor}' нет продукта '{name}' (он есть у: {'; '.join(elsewhere)})",
            )
    raise ProductNotFoundError(name, _suggest(conn, name))


def list_products(conn: sqlite3.Connection) -> list[Product]:
    """Все продукты базы по алфавиту (без учёта регистра)."""
    return [
        Product(*row) for row in conn.execute(
            "SELECT p.id, v.name, p.name FROM products p "
            "JOIN vendors v ON v.id = p.vendor_id ORDER BY p.name, v.name")
    ]


# ------------------------------------------------------ интервалы уязвимости

def _first_uncovered(ranges: list[tuple[str, str, str]], key: str) -> str | None:
    """Наименьшая версия не ниже ``key``, не попадающая ни в один диапазон.

    ``ranges`` -- тройки (start_key, fixed_key, fixed_version). Возвращает
    текст исправленной версии, на которой цепочка остановилась, либо None,
    если уже сама ``key`` не покрыта ни одним диапазоном.

    Идея: пока текущая точка лежит в каком-то диапазоне, перескакиваем на его
    конец (из всех покрывающих берём самый дальний). Всё между точкой и концом
    покрыто тем же диапазоном, поэтому результат -- именно наименьшая
    непокрытая версия. Цикл конечен: точка строго растёт, диапазонов конечное число.
    """
    current = key
    answer: str | None = None
    while True:
        covering = [r for r in ranges if r[0] <= current < r[1]]
        if not covering:
            return answer
        _, current, answer = max(covering, key=lambda r: r[1])


def _product_ranges(conn: sqlite3.Connection, product_id: int) -> list[tuple[str, str, str]]:
    return [
        (r[0], r[1], r[2]) for r in conn.execute(
            "SELECT start_key, fixed_key, fixed_version FROM vuln_ranges WHERE product_id = ?",
            (product_id,))
    ]


# ------------------------------------------------------------------- запросы

def safe_versions(
    conn: sqlite3.Connection, product: str, vendor: str | None = None,
) -> SafeVersions:
    """Версии продукта из справочника, не затронутые ни одной известной уязвимостью."""
    found = find_product(conn, product, vendor)

    total = conn.execute(
        "SELECT COUNT(*) FROM versions WHERE product_id = ?", (found.id,)).fetchone()[0]
    safe = tuple(r[0] for r in conn.execute(
        """
        SELECT v.version FROM versions v
        WHERE v.product_id = ?
          AND NOT EXISTS (SELECT 1 FROM vuln_ranges r
                          WHERE r.product_id = v.product_id
                            AND r.start_key <= v.version_key
                            AND v.version_key < r.fixed_key)
        ORDER BY v.version_key, v.version
        """, (found.id,)))

    latest = conn.execute(
        "SELECT version, version_key FROM versions WHERE product_id = ? "
        "ORDER BY version_key DESC, version DESC LIMIT 1", (found.id,)).fetchone()

    target = None
    if latest is not None and not safe:
        target = _first_uncovered(_product_ranges(conn, found.id), latest[1])

    return SafeVersions(
        product=found,
        total=total,
        safe=safe,
        latest_known=latest[0] if latest else None,
        upgrade_target=target,
    )


def vulnerabilities_for(
    conn: sqlite3.Connection, product: str, version: str, vendor: str | None = None,
) -> VulnerabilityReport:
    """Уязвимости, затрагивающие версию продукта.

    Бросает versioning.InvalidVersionError, если ``version`` записана неверно,
    и QueryError (ProductNotFoundError, AmbiguousProductError), если продукт
    не удалось определить. Версия, которой нет в справочнике, всё равно
    проверяется по диапазонам (в отчёте ``in_catalog`` будет False).
    """
    key = make_key(version)          # сначала проверяем версию: это дешёвая проверка ввода
    found = find_product(conn, product, vendor)

    in_catalog = conn.execute(
        "SELECT 1 FROM versions WHERE product_id = ? AND version_key = ? LIMIT 1",
        (found.id, key)).fetchone() is not None

    # Один бюллетень может попасть сюда несколькими строками (по числу диапазонов);
    # группируем по бюллетеню, сохраняя порядок «новые первыми».
    grouped: dict[str, dict] = {}
    for kla, date, description, start, fixed in conn.execute(
        """
        SELECT a.kla_id, a.publish_date, a.description, r.start_version, r.fixed_version
        FROM vuln_ranges r JOIN advisories a ON a.kla_id = r.kla_id
        WHERE r.product_id = ? AND r.start_key <= ? AND ? < r.fixed_key
        ORDER BY a.publish_date DESC, a.kla_id, r.fixed_key, r.start_key
        """, (found.id, key, key)):
        entry = grouped.setdefault(kla, {"date": date, "text": description, "ranges": []})
        entry["ranges"].append(VersionRange(start, fixed))

    vulnerabilities = tuple(
        Vulnerability(kla, e["date"], e["text"], tuple(e["ranges"])) for kla, e in grouped.items()
    )

    target = None
    if vulnerabilities:
        target = _first_uncovered(_product_ranges(conn, found.id), key)

    return VulnerabilityReport(
        product=found,
        version=version.strip(),
        in_catalog=in_catalog,
        vulnerabilities=vulnerabilities,
        upgrade_target=target,
    )
