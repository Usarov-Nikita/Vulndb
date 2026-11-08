import sqlite3
import unittest

from vulndb.db import SCHEMA_VERSION, connect, create_schema
from vulndb.versioning import make_key

K = make_key


class SchemaTestCase(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        create_schema(self.conn)
        self.conn.execute("INSERT INTO vendors(id, name) VALUES (1, 'Acme')")
        self.conn.execute("INSERT INTO products(id, vendor_id, name) VALUES (1, 1, 'Widget')")

    def tearDown(self):
        self.conn.close()

    # --- вспомогательные функции ---
    def add_advisory(self, kla="KLA1", date="2024-07-11", desc="test"):
        self.conn.execute(
            "INSERT INTO advisories(kla_id, description, publish_date) VALUES (?, ?, ?)",
            (kla, desc, date),
        )

    def add_range(self, kla, start, fixed, product_id=1):
        self.conn.execute(
            "INSERT INTO vuln_ranges(kla_id, product_id, start_version, start_key,"
            " fixed_version, fixed_key) VALUES (?, ?, ?, ?, ?, ?)",
            (kla, product_id, start, K(start), fixed, K(fixed)),
        )

    def add_version(self, version, product_id=1):
        self.conn.execute(
            "INSERT INTO versions(product_id, version, version_key) VALUES (?, ?, ?)",
            (product_id, version, K(version)),
        )


class StructureTests(SchemaTestCase):
    def test_tables_exist(self):
        names = {r[0] for r in self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'")}
        self.assertEqual(
            names, {"vendors", "products", "versions", "advisories", "vuln_ranges"})

    def test_foreign_keys_enabled(self):
        self.assertEqual(self.conn.execute("PRAGMA foreign_keys").fetchone()[0], 1)

    def test_schema_version_matches_constant(self):
        # PRAGMA user_version в schema.sql и SCHEMA_VERSION в db.py должны совпадать
        self.assertEqual(self.conn.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)


class VendorProductTests(SchemaTestCase):
    def test_vendor_name_unique(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("INSERT INTO vendors(name) VALUES ('Acme')")

    def test_vendor_name_not_blank(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("INSERT INTO vendors(name) VALUES ('   ')")

    def test_product_requires_existing_vendor(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("INSERT INTO products(vendor_id, name) VALUES (999, 'X')")

    def test_product_unique_per_vendor_case_insensitive(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("INSERT INTO products(vendor_id, name) VALUES (1, 'WIDGET')")

    def test_same_product_name_allowed_for_other_vendor(self):
        self.conn.execute("INSERT INTO vendors(id, name) VALUES (2, 'Globex')")
        self.conn.execute("INSERT INTO products(vendor_id, name) VALUES (2, 'Widget')")

    def test_product_lookup_ignores_case_but_is_exact(self):
        self.conn.execute("INSERT INTO products(vendor_id, name) VALUES (1, 'Widget (MSI)')")
        rows = self.conn.execute(
            "SELECT name FROM products WHERE name = ?", ("widget",)).fetchall()
        self.assertEqual([r["name"] for r in rows], ["Widget"])  # не 'Widget (MSI)'


class VersionTests(SchemaTestCase):
    def test_version_unique_per_product(self):
        self.add_version("1.0")
        with self.assertRaises(sqlite3.IntegrityError):
            self.add_version("1.0")

    def test_version_requires_existing_product(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.add_version("1.0", product_id=999)

    def test_versions_sorted_by_key_not_text(self):
        for v in ("9.0.9", "10.0.1", "9.0.10"):
            self.add_version(v)
        rows = self.conn.execute(
            "SELECT version FROM versions WHERE product_id = 1 ORDER BY version_key")
        self.assertEqual([r[0] for r in rows], ["9.0.9", "9.0.10", "10.0.1"])


class AdvisoryTests(SchemaTestCase):
    def test_valid_advisory(self):
        self.add_advisory()

    def test_duplicate_kla_rejected(self):
        self.add_advisory()
        with self.assertRaises(sqlite3.IntegrityError):
            self.add_advisory()

    def test_bad_kla_id_rejected(self):
        for bad in ("", "kla123", "XYZ123", "KLA"):
            with self.subTest(kla=bad):
                with self.assertRaises(sqlite3.IntegrityError):
                    self.add_advisory(kla=bad)

    def test_bad_dates_rejected(self):
        for bad in ("11.07.2024", "2024-7-11", "2024-13-01", "2024-02-30",
                    "2024-07-11 10:00", ""):
            with self.subTest(date=bad):
                with self.assertRaises(sqlite3.IntegrityError):
                    self.add_advisory(date=bad)

    def test_leap_day_accepted(self):
        self.add_advisory(date="2024-02-29")


class RangeTests(SchemaTestCase):
    def setUp(self):
        super().setUp()
        self.add_advisory("KLA1")

    def test_range_requires_existing_advisory_and_product(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.add_range("KLA404", "0", "2.0")
        with self.assertRaises(sqlite3.IntegrityError):
            self.add_range("KLA1", "0", "2.0", product_id=999)

    def test_inverted_range_rejected(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.add_range("KLA1", "3.0", "2.0")

    def test_empty_range_allowed(self):
        # реальный случай из данных: 128 -> 128.0 (KLA70478)
        self.add_range("KLA1", "128", "128.0")

    def test_duplicate_range_rejected(self):
        self.add_range("KLA1", "0", "2.0")
        with self.assertRaises(sqlite3.IntegrityError):
            self.add_range("KLA1", "0", "2.0")

    def test_one_advisory_many_ranges_and_products(self):
        # как в данных: один KLA, несколько диапазонов и несколько продуктов
        self.conn.execute("INSERT INTO products(id, vendor_id, name) VALUES (2, 1, 'Gadget')")
        self.add_range("KLA1", "0", "2.0", product_id=1)
        self.add_range("KLA1", "0", "5.1", product_id=1)
        self.add_range("KLA1", "0", "2.0", product_id=2)
        n = self.conn.execute(
            "SELECT COUNT(*) FROM vuln_ranges WHERE kla_id = 'KLA1'").fetchone()[0]
        self.assertEqual(n, 3)

    def test_cannot_delete_referenced_advisory(self):
        self.add_range("KLA1", "0", "2.0")
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("DELETE FROM advisories WHERE kla_id = 'KLA1'")


class VulnerabilityPredicateTests(SchemaTestCase):
    """Главное утверждение проекта, проверенное прямо в SQL:
    версия уязвима  <=>  start_key <= key(v) < fixed_key."""

    SQL_VULNERABLE = """
        SELECT v.version
        FROM versions v
        WHERE v.product_id = 1
          AND EXISTS (SELECT 1 FROM vuln_ranges r
                      WHERE r.product_id = v.product_id
                        AND r.start_key <= v.version_key
                        AND v.version_key < r.fixed_key)
        ORDER BY v.version_key
    """

    def setUp(self):
        super().setUp()
        # как у PostgreSQL в данных: правило только для ветки 15 (15 -> 15.4.1)
        for v in ("14.9", "15", "15.0.0.1", "15.4", "15.4.1", "16.0"):
            self.add_version(v)
        self.add_advisory("KLA1")
        self.add_range("KLA1", "15", "15.4.1")

    def vulnerable(self):
        return [r[0] for r in self.conn.execute(self.SQL_VULNERABLE)]

    def test_branch_rule(self):
        # 14.9 -- до начала диапазона; 15.4.1 -- уже исправлена; 16.0 -- другая ветка
        self.assertEqual(self.vulnerable(), ["15", "15.0.0.1", "15.4"])

    def test_empty_range_matches_nothing(self):
        self.add_advisory("KLA2")
        self.add_range("KLA2", "128", "128.0")
        self.add_version("128")
        self.add_version("128.0")
        self.assertEqual(self.vulnerable(), ["15", "15.0.0.1", "15.4"])

    def test_overlapping_ranges_do_not_duplicate_versions(self):
        # две записи покрывают 15.4; EXISTS даёт её один раз
        self.add_advisory("KLA3")
        self.add_range("KLA3", "15.4", "15.4.1")
        self.assertEqual(self.vulnerable(), ["15", "15.0.0.1", "15.4"])


if __name__ == "__main__":
    unittest.main()
