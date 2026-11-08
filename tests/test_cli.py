import contextlib
import io
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from vulndb.cli import build_parser, format_check, format_safe, main
from vulndb.db import connect, create_schema
from vulndb.loader import DEFAULT_VERSIONS, DEFAULT_VULNS, PROJECT_ROOT, load_data, load_files
from vulndb.queries import list_products, safe_versions, vulnerabilities_for

SCRIPT = PROJECT_ROOT / "vulndb.py"


def version_row(version="1.0", product="Widget", vendor="Acme"):
    return {"vendor": vendor, "product": product, "version": version}


def vuln_row(kla="KLA1", product="Widget", start="0", fixed="2.0", vendor="Acme",
             date="2024-07-11", desc="Test advisory"):
    return {
        "vendor": vendor, "product": product, "KLA_id": kla, "description": desc,
        "publish_date": date, "start_vuln_version": start, "fixed_version": fixed,
    }


def make_db(versions, vulns):
    conn = connect(":memory:")
    create_schema(conn)
    load_data(conn, versions, vulns)
    return conn


def run_main(*argv):
    """Вызывает main() и возвращает (код выхода, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = main(list(argv))
        except SystemExit as exc:   # так argparse сообщает об ошибках аргументов
            code = exc.code
    return code, out.getvalue(), err.getvalue()


# ------------------------------------------------------------- форматирование

class FormatSafeTests(unittest.TestCase):
    def fmt(self, versions, vulns, show_all=False):
        conn = make_db(versions, vulns)
        try:
            return format_safe(safe_versions(conn, "Widget"), show_all)
        finally:
            conn.close()

    def test_latest_safe_and_hint_about_all(self):
        lines = self.fmt([version_row(v) for v in ("1.0", "2.0", "3.0")], [])
        self.assertEqual(lines[0], "Продукт: Widget (вендор: Acme)")
        self.assertEqual(lines[1], "Версия без известных уязвимостей: 3.0")
        self.assertIn("всего таких версий: 3 из 3", lines[2])
        self.assertIn("--all", lines[2])

    def test_single_safe_version_has_no_hint(self):
        lines = self.fmt([version_row("1.0")], [])
        self.assertEqual(lines[1:], ["Версия без известных уязвимостей: 1.0"])

    def test_all_versions_listed_in_ascending_order(self):
        lines = self.fmt([version_row(v) for v in ("9.0.10", "9.0.9", "10.0.1")], [], show_all=True)
        self.assertEqual(lines[1], "Версии без известных уязвимостей (3 из 3):")
        self.assertEqual(lines[2:], ["  9.0.9", "  9.0.10", "  10.0.1"])

    def test_no_safe_versions(self):
        lines = self.fmt([version_row("1.0"), version_row("1.5")], [vuln_row(fixed="2.0")])
        text = "\n".join(lines)
        self.assertIn("Версий без известных уязвимостей в базе нет (проверено версий: 2)", text)
        self.assertIn("Самая новая известная версия: 1.5 (уязвима)", text)
        self.assertIn("Ближайшая версия без известных уязвимостей: 2.0 (в базе такой версии нет)", text)

    def test_no_versions_at_all(self):
        lines = self.fmt([], [vuln_row()])
        self.assertEqual(lines[1], "В базе нет версий этого продукта.")

    def test_warning_when_newer_versions_are_vulnerable(self):
        lines = self.fmt([version_row(v) for v in ("1.0", "2.0", "3.0")],
                         [vuln_row(start="2.5", fixed="9.0")])
        self.assertEqual(lines[1], "Версия без известных уязвимостей: 2.0")
        self.assertTrue(any("более новые версии (до 3.0), но они уязвимы" in l for l in lines))

    def test_no_warning_when_latest_known_is_safe(self):
        lines = self.fmt([version_row("1.0"), version_row("2.0")], [vuln_row(start="0", fixed="1.5")])
        self.assertFalse(any("Внимание" in l for l in lines))


class FormatCheckTests(unittest.TestCase):
    def fmt(self, versions, vulns, version):
        conn = make_db(versions, vulns)
        try:
            return format_check(vulnerabilities_for(conn, "Widget", version))
        finally:
            conn.close()

    def test_vulnerable_version(self):
        lines = self.fmt([version_row("1.0")],
                         [vuln_row(desc="Remote code execution", date="2024-07-11")], "1.0")
        self.assertEqual(lines, [
            "Продукт: Widget (вендор: Acme)",
            "Версия: 1.0",
            "Найдено уязвимостей: 1",
            "",
            "1. KLA1 (2024-07-11)",
            "   Remote code execution",
            "   Первая уязвимая версия: 0",
            "   Исправлено в: 2.0",
            "",
            "Ближайшая версия без известных уязвимостей: 2.0",
        ])

    def test_not_vulnerable(self):
        lines = self.fmt([version_row("5.0")], [vuln_row()], "5.0")
        self.assertEqual(lines[-1], "Известных уязвимостей не найдено.")
        self.assertNotIn("Найдено уязвимостей", "\n".join(lines))

    def test_version_not_in_catalog_note(self):
        lines = self.fmt([version_row("1.0")], [vuln_row()], "1.5")
        self.assertTrue(any(l.startswith("Примечание: такой версии нет в справочнике") for l in lines))

    def test_several_advisories_are_numbered_newest_first(self):
        lines = self.fmt([version_row("1.0")], [
            vuln_row("KLA1", date="2024-01-01"), vuln_row("KLA2", date="2024-09-01")], "1.0")
        text = "\n".join(lines)
        self.assertLess(text.index("1. KLA2"), text.index("2. KLA1"))

    def test_multi_range_advisory_lists_all_fixed_versions_and_earliest_start(self):
        lines = self.fmt([version_row("1.0")], [
            vuln_row("KLA1", start="0.5", fixed="9.0"), vuln_row("KLA1", start="0", fixed="2.0"),
            vuln_row("KLA1", start="1", fixed="5.0")], "1.0")
        self.assertIn("   Первая уязвимая версия: 0", lines)
        self.assertIn("   Исправлено в: 2.0, 5.0, 9.0", lines)
        self.assertEqual(sum(1 for l in lines if l.startswith("1. ")), 1)


# ---------------------------------------------------------------- команды (main)

class CommandTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.db = str(Path(cls._tmp.name) / "cli.db")
        load_files(cls.db, DEFAULT_VERSIONS, DEFAULT_VULNS)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def run_cmd(self, *argv):
        return run_main(*argv, "--db", self.db)

    # --- safe ---
    def test_safe_default_prints_latest_safe(self):
        code, out, err = self.run_cmd("safe", "Apache Tomcat")
        self.assertEqual(code, 0)
        self.assertIn("Версия без известных уязвимостей: 10.0.27", out)
        self.assertEqual(err, "")

    def test_safe_all(self):
        code, out, _ = self.run_cmd("safe", "Apache Tomcat", "--all")
        self.assertEqual(code, 0)
        self.assertIn("(2 из 226)", out)
        self.assertLess(out.index("  9.0.98"), out.index("  10.0.27"))

    def test_safe_short_flag(self):
        code, out, _ = self.run_cmd("safe", "UltraISO", "-a")
        self.assertEqual(code, 0)
        self.assertIn("(8 из 8)", out)

    def test_safe_name_without_quotes(self):
        code, out, _ = self.run_cmd("safe", "Apache", "Tomcat")
        self.assertEqual(code, 0)
        self.assertIn("Продукт: Apache Tomcat", out)

    def test_safe_case_insensitive(self):
        code, out, _ = self.run_cmd("safe", "apache tomcat")
        self.assertEqual(code, 0)
        self.assertIn("Apache Tomcat", out)

    def test_safe_product_without_safe_versions(self):
        code, out, _ = self.run_cmd("safe", "Oracle VirtualBox")
        self.assertEqual(code, 0)
        self.assertIn("Версий без известных уязвимостей в базе нет", out)
        self.assertIn("7.1.6", out)

    def test_safe_unknown_product_exit_1_with_suggestions(self):
        code, out, err = self.run_cmd("safe", "Tomcta")
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("Ошибка: продукт 'Tomcta' не найден", err)
        self.assertIn("Apache Tomcat", err)

    def test_safe_partial_name_lists_both_vlc(self):
        code, _, err = self.run_cmd("safe", "VLC")
        self.assertEqual(code, 1)
        self.assertIn("VLC media player; VLC media player (MSI installer)", err)

    def test_safe_vendor_option(self):
        code, out, _ = self.run_cmd("safe", "PuTTY", "--vendor", "simon tatham")
        self.assertEqual(code, 0)
        code, _, err = self.run_cmd("safe", "PuTTY", "--vendor", "Google")
        self.assertEqual(code, 1)
        self.assertIn("у вендора 'Google' нет продукта 'PuTTY'", err)

    def test_safe_without_product_is_usage_error(self):
        code, _, err = self.run_cmd("safe")
        self.assertEqual(code, 2)
        self.assertIn("error", err)

    # --- check ---
    def test_check_vulnerable_version(self):
        code, out, _ = self.run_cmd("check", "Apache Tomcat", "9.0.50")
        self.assertEqual(code, 0)
        self.assertIn("Найдено уязвимостей: 10", out)
        self.assertIn("1. KLA78283 (2024-12-09)", out)
        self.assertIn("Ближайшая версия без известных уязвимостей: 9.0.98", out)

    def test_check_name_without_quotes(self):
        code, out, _ = self.run_cmd("check", "Apache", "Tomcat", "9.0.50")
        self.assertEqual(code, 0)
        self.assertIn("Найдено уязвимостей: 10", out)

    def test_check_safe_version(self):
        code, out, _ = self.run_cmd("check", "Apache Tomcat", "10.0.27")
        self.assertEqual(code, 0)
        self.assertIn("Известных уязвимостей не найдено.", out)

    def test_check_version_equal_to_fixed_is_not_vulnerable(self):
        code, out, _ = self.run_cmd("check", "Apache Tomcat", "9.0.98")
        self.assertEqual(code, 0)
        self.assertIn("Известных уязвимостей не найдено.", out)

    def test_check_equal_values_same_result(self):
        _, a, _ = self.run_cmd("check", "Mozilla Thunderbird", "128.3")
        _, b, _ = self.run_cmd("check", "Mozilla Thunderbird", "128.3.0")
        self.assertEqual(a.splitlines()[2:], b.splitlines()[2:])  # без строки с версией

    def test_check_multi_range_advisory_printed_once(self):
        code, out, _ = self.run_cmd("check", "Git for Windows", "2.19.2")
        self.assertEqual(code, 0)
        self.assertEqual(out.count("KLA67449"), 1)
        self.assertIn("Исправлено в: 2.39.4, 2.40.2, 2.41.1, 2.42.2, 2.43.4, 2.44.1, 2.45.1", out)

    def test_check_version_not_in_catalog(self):
        code, out, _ = self.run_cmd("check", "Apache Tomcat", "9.0.9999")
        self.assertEqual(code, 0)
        self.assertIn("такой версии нет в справочнике", out)

    def test_check_invalid_version_exit_2(self):
        for bad in ("9.0.x", "abc", "v1"):
            with self.subTest(version=bad):
                code, out, err = self.run_cmd("check", "Apache Tomcat", bad)
                self.assertEqual(code, 2)
                self.assertEqual(out, "")
                self.assertIn("Ошибка: некорректная версия", err)

    def test_check_unknown_product_exit_1(self):
        code, _, err = self.run_cmd("check", "Nope", "1.0")
        self.assertEqual(code, 1)
        self.assertIn("не найден", err)

    def test_check_without_version_is_usage_error(self):
        code, _, err = self.run_cmd("check", "Apache Tomcat")
        self.assertEqual(code, 2)
        self.assertIn("нужны название продукта и версия", err)

    # --- products / validate ---
    def test_products(self):
        code, out, _ = self.run_cmd("products")
        self.assertEqual(code, 0)
        lines = out.splitlines()
        self.assertTrue(lines[0].startswith("Продукт"))
        self.assertTrue(lines[0].endswith("Вендор"))
        self.assertIn("Всего продуктов: 24", out)
        self.assertEqual(sum(1 for l in lines if "VLC media player" in l), 2)

    def test_validate_command(self):
        code, out, _ = self.run_cmd("validate")
        self.assertEqual(code, 0)
        self.assertIn("Итог: ошибок нет", out)

    # --- load ---
    def test_load_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "new.db"
            code, out, err = run_main("load", "--db", str(db))
            self.assertEqual(code, 0)
            self.assertIn("версий         834", out)
            self.assertIn("KLA70478", err)
            self.assertTrue(db.exists())

    def test_load_failure_exit_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "new.db"
            code, _, err = run_main("load", "--db", str(db), "--versions", str(Path(tmp) / "no.json"))
            self.assertEqual(code, 1)
            self.assertIn("Ошибка:", err)
            self.assertFalse(db.exists())

    # --- общие ошибки ---
    def test_no_command_is_usage_error(self):
        code, _, _ = run_main()
        self.assertEqual(code, 2)

    def test_unknown_command_is_usage_error(self):
        code, _, _ = run_main("frobnicate")
        self.assertEqual(code, 2)

    def test_help_exits_with_0_and_mentions_commands(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            with self.assertRaises(SystemExit) as ctx:
                main(["--help"])
        self.assertEqual(ctx.exception.code, 0)
        for word in ("load", "safe", "check", "products", "validate"):
            self.assertIn(word, out.getvalue())

    def test_commands_do_not_modify_database(self):
        before = Path(self.db).read_bytes()
        for argv in (("safe", "Apache Tomcat"), ("check", "Apache Tomcat", "9.0.50"),
                     ("products",), ("validate",)):
            self.run_cmd(*argv)
        self.assertEqual(Path(self.db).read_bytes(), before)


class DatabaseProblemTests(unittest.TestCase):
    def test_missing_database_exit_1_with_hint_and_no_file_created(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "none.db"
            for argv in (("safe", "X"), ("check", "X", "1.0"), ("products",)):
                with self.subTest(command=argv[0]):
                    code, out, err = run_main(*argv, "--db", str(db))
                    self.assertEqual(code, 1)
                    self.assertEqual(out, "")
                    self.assertIn("файл базы данных не найден", err)
                    self.assertIn("python vulndb.py load", err)
            self.assertFalse(db.exists())

    def test_sqlite_file_without_our_tables(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "other.db"
            conn = sqlite3.connect(str(db))
            conn.execute("CREATE TABLE something(x)")
            conn.commit()
            conn.close()
            code, _, err = run_main("safe", "Apache Tomcat", "--db", str(db))
            self.assertEqual(code, 1)
            self.assertIn("Ошибка:", err)
            self.assertIn("python vulndb.py load", err)
            self.assertNotIn("Traceback", err)

    def test_file_that_is_not_a_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "fake.db"
            db.write_text("это текст, а не база данных. " * 30, encoding="utf-8")
            code, _, err = run_main("safe", "Apache Tomcat", "--db", str(db))
            self.assertEqual(code, 1)
            self.assertIn("Ошибка:", err)
            self.assertNotIn("Traceback", err)


class ListProductsTests(unittest.TestCase):
    def test_sorted_ignoring_case_with_vendors(self):
        conn = make_db([version_row(product="beta"), version_row(product="Alpha", vendor="Globex"),
                        version_row(product="Gamma")], [])
        products = list_products(conn)
        self.assertEqual([(p.name, p.vendor) for p in products],
                         [("Alpha", "Globex"), ("beta", "Acme"), ("Gamma", "Acme")])
        conn.close()


# --------------------------------------------- запуск как настоящей программы

class ScriptTests(unittest.TestCase):
    """python vulndb.py ... в отдельном процессе, в том числе из чужой рабочей папки."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.dir = Path(cls._tmp.name)
        cls.db = cls.dir / "script.db"
        load_files(cls.db, DEFAULT_VERSIONS, DEFAULT_VULNS)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def run_script(self, *args, cwd=None, env_extra=None, module=False, encoding="utf-8"):
        env = dict(os.environ, PYTHONIOENCODING=encoding)
        env.update(env_extra or {})
        command = [sys.executable, "-m", "vulndb"] if module else [sys.executable, str(SCRIPT)]
        return subprocess.run(
            command + list(args) + ["--db", str(self.db)],
            cwd=cwd or PROJECT_ROOT, capture_output=True, text=True, encoding=encoding, env=env,
        )

    def test_script_from_project_root(self):
        r = self.run_script("safe", "Apache Tomcat")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("10.0.27", r.stdout)

    def test_script_from_another_directory(self):
        r = self.run_script("check", "Apache Tomcat", "9.0.50", cwd=self.dir)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Найдено уязвимостей: 10", r.stdout)

    def test_module_entry_point(self):
        r = self.run_script("safe", "Apache Tomcat", module=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("10.0.27", r.stdout)

    def test_exit_codes(self):
        self.assertEqual(self.run_script("safe", "Nope").returncode, 1)
        self.assertEqual(self.run_script("check", "Apache Tomcat", "x.y").returncode, 2)
        self.assertEqual(self.run_script("check", "Apache Tomcat").returncode, 2)

    def test_old_console_encoding_does_not_crash(self):
        # В кодировке cp1251 нет стрелки в отчёте validate; без защиты был бы UnicodeEncodeError.
        # Вывод читаем в той же кодировке, в которой его печатает программа.
        r = self.run_script("validate", encoding="cp1251")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("Traceback", r.stderr)
        self.assertIn("Итог: ошибок нет", r.stdout)       # кириллица выведена правильно
        self.assertIn("128 ? 128.0", r.stdout)             # стрелка заменена на знак вопроса

    def test_closed_pipe_prints_no_traceback(self):
        env = dict(os.environ, PYTHONIOENCODING="utf-8")
        proc = subprocess.Popen(
            [sys.executable, str(SCRIPT), "safe", "KeePass Password Safe", "--all", "--db", str(self.db)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        proc.stdout.read(10)    # читаем немного и закрываем трубу, как это делает `head`
        proc.stdout.close()
        stderr = proc.stderr.read().decode("utf-8", "replace")
        proc.wait()
        proc.stderr.close()
        self.assertNotIn("Traceback", stderr)


class ParserTests(unittest.TestCase):
    def test_default_db_is_next_to_the_program(self):
        args = build_parser().parse_args(["safe", "X"])
        self.assertEqual(args.db, PROJECT_ROOT / "vulns.db")

    def test_check_collects_words(self):
        args = build_parser().parse_args(["check", "Apache", "Tomcat", "9.0.50", "--vendor", "ASF"])
        self.assertEqual(args.words, ["Apache", "Tomcat", "9.0.50"])
        self.assertEqual(args.vendor, "ASF")


if __name__ == "__main__":
    unittest.main()
