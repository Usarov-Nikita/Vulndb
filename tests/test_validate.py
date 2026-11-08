import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from vulndb.db import SCHEMA_VERSION, connect, connect_readonly, create_schema
from vulndb.loader import (
    DEFAULT_VERSIONS,
    DEFAULT_VULNS,
    PROJECT_ROOT,
    LoadError,
    load_data,
    load_files,
    read_json,
)
from vulndb.validate import ERROR, INFO, WARNING, CheckResult, ValidationReport, validate
from vulndb.versioning import make_key


def version_row(version="1.0", product="Widget", vendor="Acme"):
    return {"vendor": vendor, "product": product, "version": version}


def vuln_row(kla="KLA1", product="Widget", start="0", fixed="2.0", vendor="Acme"):
    return {
        "vendor": vendor, "product": product, "KLA_id": kla, "description": "Test",
        "publish_date": "2024-07-11", "start_vuln_version": start, "fixed_version": fixed,
    }


def make_db(versions, vulns):
    conn = connect(":memory:")
    create_schema(conn)
    load_data(conn, versions, vulns)
    return conn


def failed_ids(report, severity=None):
    return sorted(r.id for r in report.failed(severity))


class HealthyDatabaseTests(unittest.TestCase):
    def test_small_consistent_database_passes_everything(self):
        conn = make_db(
            [version_row("1.0"), version_row("2.0")],
            [vuln_row(start="0", fixed="2.0")],
        )
        report = validate(conn)
        self.assertTrue(report.ok)
        self.assertEqual(report.failed(), [])
        conn.close()


class RealDataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.conn = connect(":memory:")
        create_schema(cls.conn)
        load_data(cls.conn, read_json(DEFAULT_VERSIONS), read_json(DEFAULT_VULNS))
        cls.report = validate(cls.conn)

    @classmethod
    def tearDownClass(cls):
        cls.conn.close()

    def by_id(self, check_id):
        return next(r for r in self.report.results if r.id == check_id)

    def test_database_is_usable(self):
        self.assertTrue(self.report.ok)
        self.assertEqual(self.report.failed(ERROR), [])

    def test_exactly_the_known_findings(self):
        self.assertEqual(failed_ids(self.report, WARNING), ["no_empty_ranges"])
        self.assertEqual(
            failed_ids(self.report, INFO),
            ["fixed_in_catalog", "products_have_safe_version", "ranges_match_versions"],
        )

    def test_empty_range_is_the_known_one(self):
        problems = self.by_id("no_empty_ranges").problems
        self.assertEqual(len(problems), 1)
        self.assertIn("KLA70478", problems[0])

    def test_fixed_versions_missing_from_catalog_compared_by_value(self):
        problems = self.by_id("fixed_in_catalog").problems
        self.assertEqual(len(problems), 17)
        # 128.3 и 128.4 есть в справочнике как 128.3.0 и 128.4.0 -- это те же версии
        joined = "\n".join(problems)
        self.assertNotIn("Mozilla Thunderbird 128.3:", joined)
        self.assertNotIn("Mozilla Thunderbird 128.4:", joined)

    def test_rules_matching_no_known_version(self):
        self.assertEqual(len(self.by_id("ranges_match_versions").problems), 8)

    def test_product_without_safe_version(self):
        self.assertEqual(
            self.by_id("products_have_safe_version").problems,
            ["Oracle VirtualBox: все известные версии уязвимы"],
        )

    def test_cross_feed_checks_pass(self):
        for check_id in ("products_have_versions", "products_have_ranges",
                         "advisories_have_ranges", "vendors_have_products"):
            with self.subTest(check=check_id):
                self.assertTrue(self.by_id(check_id).passed)

    def test_report_text(self):
        text = "\n".join(self.report.lines())
        self.assertIn("[ OK ] Внешние ключи без нарушений", text)
        self.assertIn("[ПРЕДУПРЕЖДЕНИЕ] Нет пустых диапазонов", text)
        self.assertIn("Итог: ошибок нет; предупреждений 1, замечаний 3.", text)
        self.assertIn("База пригодна к работе.", text)


class CorruptionDetectionTests(unittest.TestCase):
    """Намеренно портим исправную базу -- проверки должны это заметить."""

    def setUp(self):
        self.conn = make_db([version_row("1.0"), version_row("2.0")], [vuln_row()])

    def tearDown(self):
        self.conn.close()

    def test_wrong_version_key(self):
        self.conn.execute("UPDATE versions SET version_key = 'junk' WHERE version = '1.0'")
        report = validate(self.conn)
        self.assertFalse(report.ok)
        self.assertIn("version_keys", failed_ids(report, ERROR))
        problem = next(r for r in report.results if r.id == "version_keys").problems[0]
        self.assertIn("Widget 1.0", problem)

    def test_wrong_range_key(self):
        # ключ конца подменён на ключ другой версии, но порядок start <= fixed сохранён
        self.conn.execute("UPDATE vuln_ranges SET fixed_key = ?", (make_key("9.9"),))
        report = validate(self.conn)
        self.assertIn("range_keys", failed_ids(report, ERROR))

    def test_unparsable_version_text(self):
        self.conn.execute("UPDATE versions SET version = 'abc' WHERE version = '1.0'")
        report = validate(self.conn)
        self.assertIn("version_keys", failed_ids(report, ERROR))

    def test_foreign_key_violation(self):
        self.conn.execute("PRAGMA foreign_keys = OFF")
        self.conn.execute(
            "INSERT INTO versions(product_id, version, version_key) VALUES (999, '1.0', ?)",
            (make_key("1.0"),),
        )
        report = validate(self.conn)
        self.assertFalse(report.ok)
        self.assertIn("foreign_keys", failed_ids(report, ERROR))

    def test_report_lists_problem_details_and_error_summary(self):
        self.conn.execute("UPDATE versions SET version_key = 'junk'")
        text = "\n".join(validate(self.conn).lines())
        self.assertIn("[ОШИБКА] Ключи версий соответствуют их тексту — отклонений: 2", text)
        self.assertIn("Пользоваться базой нельзя.", text)


class WarningAndNoteTests(unittest.TestCase):
    def check(self, versions, vulns, severity=None):
        conn = make_db(versions, vulns)
        try:
            return validate(conn)
        finally:
            conn.close()

    def test_product_with_rules_but_no_versions(self):
        report = self.check([], [vuln_row()])
        self.assertEqual(failed_ids(report, WARNING), ["products_have_versions"])
        self.assertTrue(report.ok)  # это не ошибка

    def test_product_with_versions_but_no_rules(self):
        report = self.check([version_row("1.0")], [])
        self.assertEqual(failed_ids(report), ["products_have_ranges"])
        self.assertTrue(report.ok)

    def test_advisory_without_ranges_and_vendor_without_products(self):
        conn = make_db([version_row("1.0")], [vuln_row()])
        conn.execute("INSERT INTO advisories VALUES ('KLA999', 'orphan', '2024-01-01')")
        conn.execute("INSERT INTO vendors(name) VALUES ('Lonely')")
        report = validate(conn)
        self.assertEqual(
            failed_ids(report, WARNING), ["advisories_have_ranges", "vendors_have_products"])
        conn.close()

    def test_equivalent_versions(self):
        report = self.check([version_row("1.0"), version_row("1.0.0"), version_row("2.0")],
                            [vuln_row(start="0", fixed="2.0")])
        self.assertEqual(failed_ids(report, WARNING), ["no_equivalent_versions"])
        problem = report.failed(WARNING)[0].problems[0]
        self.assertIn("1.0", problem)
        self.assertIn("1.0.0", problem)

    def test_empty_range(self):
        report = self.check([version_row("128")], [vuln_row(kla="KLA7", start="128", fixed="128.0")])
        self.assertEqual(failed_ids(report, WARNING), ["no_empty_ranges"])
        self.assertIn("KLA7", report.failed(WARNING)[0].problems[0])

    def test_fixed_version_missing_from_catalog(self):
        report = self.check([version_row("1.0")], [vuln_row(fixed="2.0")])
        self.assertIn("fixed_in_catalog", failed_ids(report, INFO))

    def test_fixed_version_present_under_different_spelling(self):
        report = self.check([version_row("1.0"), version_row("2.0.0")], [vuln_row(fixed="2")])
        self.assertNotIn("fixed_in_catalog", failed_ids(report))

    def test_rule_matching_no_known_version(self):
        report = self.check([version_row("5.0")], [vuln_row(start="0", fixed="2.0")])
        self.assertIn("ranges_match_versions", failed_ids(report, INFO))

    def test_empty_range_not_double_reported_as_dead_rule(self):
        report = self.check([version_row("1.0")], [vuln_row(start="3", fixed="3.0")])
        self.assertIn("no_empty_ranges", failed_ids(report))
        self.assertNotIn("ranges_match_versions", failed_ids(report))

    def test_product_with_only_vulnerable_versions(self):
        report = self.check([version_row("1.0"), version_row("1.5")], [vuln_row(fixed="2.0")])
        self.assertIn("products_have_safe_version", failed_ids(report, INFO))

    def test_product_with_a_safe_version(self):
        report = self.check([version_row("1.0"), version_row("2.0")], [vuln_row(fixed="2.0")])
        self.assertNotIn("products_have_safe_version", failed_ids(report))


class StructureTests(unittest.TestCase):
    def test_database_without_tables(self):
        conn = connect(":memory:")
        report = validate(conn)
        self.assertFalse(report.ok)
        self.assertEqual([r.id for r in report.results], ["structure"])  # дальше проверять нечего
        self.assertIn("нет таблицы vendors", report.results[0].problems)
        conn.close()

    def test_wrong_schema_version(self):
        conn = connect(":memory:")
        create_schema(conn)
        conn.execute("PRAGMA user_version = 99")
        report = validate(conn)
        self.assertFalse(report.ok)
        self.assertIn(f"версия схемы 99, ожидалась {SCHEMA_VERSION}", report.results[0].problems)
        conn.close()

    def test_file_that_is_not_a_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fake.db"
            path.write_text("это просто текст, а не база данных. " * 20, encoding="utf-8")
            conn = connect_readonly(path)
            try:
                report = validate(conn)
            finally:
                conn.close()
        self.assertFalse(report.ok)
        self.assertIn("не читается как база SQLite", report.results[0].problems[0])


class ReportFormattingTests(unittest.TestCase):
    def test_long_problem_lists_are_truncated(self):
        report = ValidationReport([
            CheckResult("x", "Проверка", WARNING, [f"проблема {i}" for i in range(20)]),
        ])
        text = "\n".join(report.lines(max_details=3))
        self.assertIn("отклонений: 20", text)
        self.assertIn("проблема 2", text)
        self.assertNotIn("проблема 3", text)
        self.assertIn("… и ещё 17", text)

    def test_severity_labels(self):
        report = ValidationReport([
            CheckResult("a", "Тест А", ERROR, ["x"]),
            CheckResult("b", "Тест Б", WARNING, ["x"]),
            CheckResult("c", "Тест В", INFO, ["x"]),
            CheckResult("d", "Тест Г", INFO, []),
        ])
        text = "\n".join(report.lines())
        for expected in ("[ОШИБКА] Тест А", "[ПРЕДУПРЕЖДЕНИЕ] Тест Б",
                         "[ЗАМЕЧАНИЕ] Тест В", "[ OK ] Тест Г"):
            self.assertIn(expected, text)
        self.assertFalse(report.ok)


class ConnectReadonlyTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_missing_file_is_not_created(self):
        path = self.dir / "missing.db"
        with self.assertRaises(FileNotFoundError):
            connect_readonly(path)
        self.assertFalse(path.exists())

    def test_cannot_write(self):
        path = self.dir / "a.db"
        conn = connect(path)
        create_schema(conn)
        conn.commit()
        conn.close()
        ro = connect_readonly(path)
        try:
            with self.assertRaises(sqlite3.OperationalError):
                ro.execute("INSERT INTO vendors(name) VALUES ('x')")
        finally:
            ro.close()

    def test_path_with_spaces_and_cyrillic(self):
        folder = self.dir / "Папка с пробелом"
        folder.mkdir()
        path = folder / "база данных.db"
        conn = connect(path)
        create_schema(conn)
        conn.commit()
        conn.close()
        ro = connect_readonly(path)
        try:
            self.assertEqual(ro.execute("SELECT COUNT(*) FROM vendors").fetchone()[0], 0)
        finally:
            ro.close()

    def test_foreign_keys_enabled(self):
        path = self.dir / "a.db"
        conn = connect(path)
        create_schema(conn)
        conn.commit()
        conn.close()
        ro = connect_readonly(path)
        try:
            self.assertEqual(ro.execute("PRAGMA foreign_keys").fetchone()[0], 1)
        finally:
            ro.close()


class LoaderIntegrationTests(unittest.TestCase):
    def test_load_files_aborts_when_validation_fails(self):
        failing = ValidationReport([CheckResult("version_keys", "Ключи версий", ERROR, ["Widget 1.0: плохо"])])
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "x.db"
            with mock.patch("vulndb.loader.validate", return_value=failing):
                with self.assertRaises(LoadError) as ctx:
                    load_files(db, DEFAULT_VERSIONS, DEFAULT_VULNS)
            self.assertIn("проверка целостности", str(ctx.exception))
            self.assertIn("Widget 1.0: плохо", str(ctx.exception))
            self.assertEqual(list(Path(tmp).iterdir()), [])  # ни базы, ни временных файлов

    def test_load_files_tolerates_warnings_and_notes(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "x.db"
            load_files(db, DEFAULT_VERSIONS, DEFAULT_VULNS)  # в данных есть предупреждение и замечания
            self.assertTrue(db.exists())


class CommandLineTests(unittest.TestCase):
    def run_validate(self, *args):
        env = dict(os.environ, PYTHONIOENCODING="utf-8")
        return subprocess.run(
            [sys.executable, "-m", "vulndb.validate", *args],
            cwd=PROJECT_ROOT, capture_output=True, text=True, encoding="utf-8", env=env,
        )

    def test_healthy_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "ok.db"
            load_files(db, DEFAULT_VERSIONS, DEFAULT_VULNS)
            result = self.run_validate("--db", str(db))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Итог: ошибок нет", result.stdout)
        self.assertIn("KLA70478", result.stdout)
        self.assertIn("Oracle VirtualBox", result.stdout)

    def test_corrupted_database_returns_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "bad.db"
            load_files(db, DEFAULT_VERSIONS, DEFAULT_VULNS)
            conn = connect(db)
            conn.execute("UPDATE versions SET version_key = 'junk' WHERE id = 1")
            conn.commit()
            conn.close()
            result = self.run_validate("--db", str(db))
        self.assertEqual(result.returncode, 1)
        self.assertIn("[ОШИБКА]", result.stdout)
        self.assertIn("Пользоваться базой нельзя", result.stdout)

    def test_missing_database_returns_1_and_creates_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "nope.db"
            result = self.run_validate("--db", str(db))
            self.assertEqual(result.returncode, 1)
            self.assertIn("Ошибка:", result.stderr)
            self.assertIn("не найден", result.stderr)
            self.assertFalse(db.exists())

    def test_validation_does_not_modify_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "ok.db"
            load_files(db, DEFAULT_VERSIONS, DEFAULT_VULNS)
            before = db.read_bytes()
            self.run_validate("--db", str(db))
            self.assertEqual(db.read_bytes(), before)
            self.assertEqual(sorted(p.name for p in Path(tmp).iterdir()), ["ok.db"])


if __name__ == "__main__":
    unittest.main()
