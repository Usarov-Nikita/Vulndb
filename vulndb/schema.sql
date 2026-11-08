-- Схема базы данных: продукты, их версии и уязвимости.
--
-- Модель:
--   vendors ──< products ──< versions            (справочник версий, фид 2)
--                  │
--                  └──< vuln_ranges >── advisories   (уязвимости, фид 1)
--
--   advisory   -- бюллетень безопасности (KLA): id, описание, дата публикации.
--   vuln_range -- «бюллетень KLA затрагивает продукт P в версиях [start, fixed)».
--
-- Бюллетень и диапазон разделены намеренно: один KLA_id встречается в данных
-- в нескольких строках (разные продукты или несколько диапазонов у одного
-- продукта), а описание и дата у него общие.
--
-- Версии хранятся дважды: как исходный текст (для вывода) и как ключ
-- сортировки (для сравнения, см. versioning.make_key). Ключ считает загрузчик;
-- SQL-ограничения проверяют только порядок ключей, но не их соответствие тексту.
--
-- Уязвимость версии v продукта P:  start_key <= key(v) AND key(v) < fixed_key
--
-- Примечание: PRAGMA foreign_keys действует только на одно соединение,
-- поэтому включается в db.connect(), а не здесь.
--
-- Файл содержит только CREATE (без IF NOT EXISTS): базу всегда создаёт
-- загрузчик с нуля.

PRAGMA user_version = 1;

CREATE TABLE vendors (
    id    INTEGER PRIMARY KEY,
    name  TEXT NOT NULL UNIQUE
          CHECK (length(trim(name)) > 0)
);

CREATE TABLE products (
    id         INTEGER PRIMARY KEY,
    vendor_id  INTEGER NOT NULL REFERENCES vendors(id),
    -- NOCASE: «apache tomcat» == «Apache Tomcat» (для ASCII-названий)
    name       TEXT NOT NULL COLLATE NOCASE
               CHECK (length(trim(name)) > 0),
    UNIQUE (vendor_id, name)
);

-- Поиск продукта по названию (запрос CLI).
CREATE INDEX idx_products_name ON products(name);

CREATE TABLE versions (
    id          INTEGER PRIMARY KEY,
    product_id  INTEGER NOT NULL REFERENCES products(id),
    version     TEXT NOT NULL,   -- как в фиде, например '9.0.10'
    version_key TEXT NOT NULL,   -- ключ сортировки
    UNIQUE (product_id, version)
);

-- Самая новая безопасная версия: перебор версий продукта в порядке ключа.
CREATE INDEX idx_versions_product_key ON versions(product_id, version_key);

CREATE TABLE advisories (
    kla_id        TEXT PRIMARY KEY
                  CHECK (kla_id GLOB 'KLA[0-9]*'),
    description   TEXT NOT NULL,
    -- ISO-дата YYYY-MM-DD. «date(x) IS x» отклоняет несуществующие даты
    -- (2024-02-30), потому что date() вернёт для них NULL.
    publish_date  TEXT NOT NULL
                  CHECK (publish_date GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'
                         AND date(publish_date) IS publish_date)
);

CREATE TABLE vuln_ranges (
    id             INTEGER PRIMARY KEY,
    kla_id         TEXT    NOT NULL REFERENCES advisories(kla_id),
    product_id     INTEGER NOT NULL REFERENCES products(id),
    start_version  TEXT    NOT NULL,  -- первая уязвимая версия ('0' = с самого начала)
    start_key      TEXT    NOT NULL,
    fixed_version  TEXT    NOT NULL,  -- первая исправленная версия (сама уже НЕ уязвима)
    fixed_key      TEXT    NOT NULL,
    -- «<=», а не «<»: в данных есть запись 128 -> 128.0 (KLA70478), где ключи
    -- равны. Интервал [128, 128.0) пуст, ни одна версия под него не попадает.
    -- Перевёрнутые диапазоны (start > fixed) запрещены.
    CHECK (start_key <= fixed_key),
    UNIQUE (kla_id, product_id, start_version, fixed_version)
);

-- Поиск правил для продукта и проверка попадания версии в диапазон.
CREATE INDEX idx_ranges_product ON vuln_ranges(product_id, start_key, fixed_key);
-- Обратная связь: все диапазоны бюллетеня.
CREATE INDEX idx_ranges_kla ON vuln_ranges(kla_id);
