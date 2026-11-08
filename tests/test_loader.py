import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from vulndb.db import connect, create_schema
from vulndb.loader import (
    DEFAULT_VERSIONS,
    DEFAULT_VULNS,
    PROJECT_ROOT,
    LoadError,
    load_data,
    load_files,
    read_json,
)
from vulndb.versioning import make_key


def version_row(vendor="Acme", product="Widget", version="1.0"):
    return {"vendor": vendor, "product": product, "version": version}


def vuln_row(kla="KLA1", vendor="Acme", product="Widget", start="0", fixed="2.0",
             date="2024-07-11", desc="Test advisory"):
    return {
        "vendor": vendor, "product": product, "KLA_id": kla, "description": desc,
        "publish_date": date, "start_vuln_version": start, "fixed_version": fixed,
    }


def fresh_conn():
    conn = connect(":memory:")
    create_schema(conn)
    return conn


class RealDataTests(unittest.TestCase):
    """Загрузка настоящих фидов из data/."""

    @classmethod
    def setUpClass(cls):
        cls.conn = fresh_conn()
        cls.report = load_data(cls.conn, read_json(DEFAULT_VERSIONS), read_json(DEFAULT_VULNS))

    @classmethod
    def tearDownClass(cls):
        cls.conn.close()

    def test_row_counts(self):
        r = self.report
        self.assertEqual(
            (r.vendors, r.products, r.versions, r.advisories, r.ranges),
            (17, 24, 834, 105, 135),
        )

    def test_counts_match_database(self):
        for table, expected in (("vendors", 17), ("products", 24), ("versions", 834),
                                ("advisories", 105), ("vuln_ranges", 135)):
            with self.subTest(table=table):
                n = self.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                self.assertEqual(n, expected)

    def test_only_warning_is_the_known_empty_range(self):
        self.assertEqual(len(self.report.warnings), 1)
        self.assertIn("KLA70478", self.report.warnings[0])
        self.assertIn("пуст", self.report.warnings[0])

    def test_keys_are_computed_by_make_key(self):
        for row in self.conn.execute("SELECT version, version_key FROM versions"):
            self.assertEqual(row["version_key"], make_key(row["version"]))
        for row in self.conn.execute(
                "SELECT start_version, start_key, fixed_version, fixed_key FROM vuln_ranges"):
            self.assertEqual(row["start_key"], make_key(row["start_version"]))
            self.assertEqual(row["fixed_key"], make_key(row["fixed_version"]))

    def test_no_foreign_key_violations(self):
        self.assertEqual(self.conn.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_product_shared_between_feeds_is_one_row(self):
        n = self.conn.execute(
            "SELECT COUNT(*) FROM products WHERE name = 'Apache Tomcat'").fetchone()[0]
        self.assertEqual(n, 1)

    def test_every_product_has_versions_and_ranges(self):
        orphans = self.conn.execute("""
            SELECT name FROM products p
            WHERE NOT EXISTS (SELECT 1 FROM versions v WHERE v.product_id = p.id)
               OR NOT EXISTS (SELECT 1 FROM vuln_ranges r WHERE r.product_id = p.id)
        """).fetchall()
        self.assertEqual(orphans, [])

    def test_safe_versions_match_expected(self):
        sql = """
            SELECT COUNT(*) FROM versions v JOIN products p ON p.id = v.product_id
            WHERE p.name = ? AND NOT EXISTS (
                SELECT 1 FROM vuln_ranges r WHERE r.product_id = v.product_id
                  AND r.start_key <= v.version_key AND v.version_key < r.fixed_key)
        """
        for product, expected in (("Apache Tomcat", 2), ("Oracle VirtualBox", 0),
                                  ("KeePass Password Safe", 44)):
            with self.subTest(product=product):
                self.assertEqual(self.conn.execute(sql, (product,)).fetchone()[0], expected)


class RecordValidationTests(unittest.TestCase):
    def setUp(self):
        self.conn = fresh_conn()

    def tearDown(self):
        self.conn.close()

    def load(self, versions=(), vulns=()):
        return load_data(self.conn, list(versions), list(vulns))

    def assert_load_error(self, versions=(), vulns=(), *fragments):
        with self.assertRaises(LoadError) as ctx:
            self.load(versions, vulns)
        for fragment in fragments:
            self.assertIn(fragment, str(ctx.exception))

    def test_missing_field(self):
        bad = version_row()
        del bad["product"]
        self.assert_load_error([bad], [], "запись №1", "нет поля 'product'")

    def test_empty_field(self):
        self.assert_load_error([version_row(vendor="  ")], [], "поле 'vendor' пустое")

    def test_non_string_field(self):
        self.assert_load_error([version_row(version=2.0)], [], "должно быть строкой", "float")

    def test_invalid_version_in_versions_feed(self):
        self.assert_load_error(
            [version_row(), version_row(version="1.2.x")],
            [], "фид версий", "запись №2", "'version'", "1.2.x")

    def test_invalid_version_in_vulns_feed(self):
        self.assert_load_error([], [vuln_row(fixed="two")], "фид уязвимостей", "'fixed_version'")

    def test_inverted_range(self):
        self.assert_load_error([], [vuln_row(start="3.0", fixed="2.0")],
                               "KLA1", "больше первой исправленной")

    def test_bad_date(self):
        self.assert_load_error([], [vuln_row(date="11.07.2024")], "KLA1", "ГГГГ-ММ-ДД")

    def test_bad_kla_id(self):
        self.assert_load_error([], [vuln_row(kla="XYZ1")], "XYZ1", "KLA12345")

    def test_conflicting_advisory_description(self):
        self.assert_load_error(
            [], [vuln_row(desc="one"), vuln_row(product="Gadget", desc="two")],
            "запись №2", "отличаются")

    def test_failed_load_rolls_back(self):
        with self.assertRaises(LoadError):
            self.load([version_row()], [vuln_row(date="bad")])
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM vendors").fetchone()[0], 0)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM versions").fetchone()[0], 0)

    def test_non_empty_database_rejected(self):
        self.load([version_row()], [])
        with self.assertRaises(LoadError) as ctx:
            self.load([version_row()], [])
        self.assertIn("не пуста", str(ctx.exception))


class NormalizationTests(unittest.TestCase):
    def setUp(self):
        self.conn = fresh_conn()

    def tearDown(self):
        self.conn.close()

    def test_same_product_in_both_feeds_ignoring_case_and_spaces(self):
        report = load_data(
            self.conn,
            [version_row(vendor="Acme", product="Widget")],
            [vuln_row(vendor=" ACME ", product="widget")],
        )
        self.assertEqual((report.vendors, report.products), (1, 1))
        name = self.conn.execute("SELECT name FROM products").fetchone()[0]
        self.assertEqual(name, "Widget")  # написание первой записи

    def test_whitespace_is_stripped(self):
        load_data(self.conn, [version_row(version=" 1.5 ")], [])
        self.assertEqual(self.conn.execute("SELECT version FROM versions").fetchone()[0], "1.5")

    def test_duplicate_versions_loaded_once_with_warning(self):
        report = load_data(self.conn, [version_row(), version_row(), version_row(version="2.0")], [])
        self.assertEqual(report.versions, 2)
        self.assertEqual(len(report.warnings), 1)
        self.assertIn("1", report.warnings[0])

    def test_duplicate_ranges_loaded_once_with_warning(self):
        report = load_data(self.conn, [], [vuln_row(), vuln_row()])
        self.assertEqual((report.advisories, report.ranges), (1, 1))
        self.assertEqual(len(report.warnings), 1)

    def test_equal_ranges_written_differently_collapse(self):
        report = load_data(self.conn, [], [vuln_row(start="1", fixed="2"), vuln_row(start="1.0", fixed="2.0.0")])
        self.assertEqual(report.ranges, 1)

    def test_one_advisory_many_products_and_ranges(self):
        report = load_data(self.conn, [], [
            vuln_row(product="Widget", fixed="2.0"),
            vuln_row(product="Widget", fixed="5.1"),
            vuln_row(product="Gadget", fixed="2.0"),
        ])
        self.assertEqual((report.advisories, report.products, report.ranges), (1, 2, 3))

    def test_empty_range_is_stored_with_warning(self):
        report = load_data(self.conn, [], [vuln_row(kla="KLA7", start="128", fixed="128.0")])
        self.assertEqual(report.ranges, 1)
        self.assertEqual(len(report.warnings), 1)
        self.assertIn("KLA7", report.warnings[0])


class ReadJsonTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, name, content, encoding="utf-8"):
        path = self.dir / name
        path.write_bytes(content.encode(encoding) if isinstance(content, str) else content)
        return path

    def test_reads_array_of_objects(self):
        self.assertEqual(read_json(self.write("a.json", '[{"a": 1}]')), [{"a": 1}])

    def test_bom_is_tolerated(self):
        self.assertEqual(read_json(self.write("a.json", "\ufeff[]")), [])

    def test_missing_file(self):
        with self.assertRaises(LoadError) as ctx:
            read_json(self.dir / "nope.json")
        self.assertIn("не найден", str(ctx.exception))

    def test_invalid_json(self):
        with self.assertRaises(LoadError) as ctx:
            read_json(self.write("a.json", "[{"))
        self.assertIn("некорректный JSON", str(ctx.exception))

    def test_not_an_array(self):
        with self.assertRaises(LoadError) as ctx:
            read_json(self.write("a.json", '{"a": 1}'))
        self.assertIn("массив", str(ctx.exception))

    def test_array_of_non_objects(self):
        with self.assertRaises(LoadError) as ctx:
            read_json(self.write("a.json", '[{"a": 1}, 5]'))
        self.assertIn("запись №2", str(ctx.exception))

    def test_not_utf8(self):
        with self.assertRaises(LoadError) as ctx:
            read_json(self.write("a.json", "[]".encode("utf-16")))
        self.assertIn("UTF-8", str(ctx.exception))


class LoadFilesTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.db = self.dir / "sub" / "test.db"

    def tearDown(self):
        self._tmp.cleanup()

    def write_json(self, name, rows):
        path = self.dir / name
        path.write_text(json.dumps(rows), encoding="utf-8")
        return path

    def counts(self, path):
        conn = connect(path)
        try:
            return {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                    for t in ("vendors", "products", "versions", "advisories", "vuln_ranges")}
        finally:
            conn.close()

    def test_creates_database_with_all_data(self):
        report = load_files(self.db, DEFAULT_VERSIONS, DEFAULT_VULNS)
        self.assertTrue(self.db.exists())
        self.assertEqual(self.counts(self.db),
                         {"vendors": 17, "products": 24, "versions": 834,
                          "advisories": 105, "vuln_ranges": 135})
        self.assertEqual(report.versions, 834)

    def test_no_temporary_files_left(self):
        load_files(self.db, DEFAULT_VERSIONS, DEFAULT_VULNS)
        self.assertEqual(sorted(p.name for p in self.db.parent.iterdir()), ["test.db"])

    def test_reload_replaces_database_cleanly(self):
        load_files(self.db, DEFAULT_VERSIONS, DEFAULT_VULNS)
        load_files(self.db, DEFAULT_VERSIONS, DEFAULT_VULNS)
        self.assertEqual(self.counts(self.db)["versions"], 834)

    def test_failed_load_creates_nothing(self):
        versions = self.write_json("v.json", [version_row()])
        vulns = self.write_json("x.json", [vuln_row(date="bad")])
        with self.assertRaises(LoadError):
            load_files(self.db, versions, vulns)
        self.assertFalse(self.db.exists())
        self.assertEqual(list(self.db.parent.iterdir()), [])

    def test_failed_load_keeps_existing_database(self):
        good_v = self.write_json("v.json", [version_row()])
        good_x = self.write_json("x.json", [vuln_row()])
        load_files(self.db, good_v, good_x)
        before = self.counts(self.db)

        bad_x = self.write_json("bad.json", [vuln_row(date="bad")])
        with self.assertRaises(LoadError):
            load_files(self.db, good_v, bad_x)
        self.assertEqual(self.counts(self.db), before)
        self.assertEqual(sorted(p.name for p in self.db.parent.iterdir()), ["test.db"])

    def test_missing_input_file_creates_nothing(self):
        with self.assertRaises(LoadError):
            load_files(self.db, self.dir / "none.json", DEFAULT_VULNS)
        self.assertFalse(self.db.exists())


class CommandLineTests(unittest.TestCase):
    def run_loader(self, *args):
        env = dict(os.environ, PYTHONIOENCODING="utf-8")
        return subprocess.run(
            [sys.executable, "-m", "vulndb.loader", *args],
            cwd=PROJECT_ROOT, capture_output=True, text=True, encoding="utf-8", env=env,
        )

    def test_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "cli.db"
            result = self.run_loader("--db", str(db))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(db.exists())
            self.assertIn("834", result.stdout)
            self.assertIn("KLA70478", result.stderr)  # предупреждение о пустом диапазоне

    def test_error_exit_code_and_message(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "cli.db"
            result = self.run_loader("--db", str(db), "--versions", str(Path(tmp) / "no.json"))
            self.assertEqual(result.returncode, 1)
            self.assertIn("Ошибка:", result.stderr)
            self.assertIn("не найден", result.stderr)
            self.assertFalse(db.exists())


if __name__ == "__main__":
    unittest.main()
