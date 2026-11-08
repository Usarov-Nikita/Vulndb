import json
import tempfile
import unittest
from collections import defaultdict
from pathlib import Path

from vulndb.db import connect, connect_readonly, create_schema
from vulndb.loader import DEFAULT_VERSIONS, DEFAULT_VULNS, load_data, load_files, read_json
from vulndb.queries import (
    AmbiguousProductError,
    ProductNotFoundError,
    QueryError,
    VersionRange,
    find_product,
    safe_versions,
    vulnerabilities_for,
)
from vulndb.versioning import InvalidVersionError


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


# ---------------------------------------------------------------- поиск продукта

class FindProductTests(unittest.TestCase):
    def setUp(self):
        self.conn = make_db(
            [version_row(product="Widget"), version_row(product="Widget (MSI)"),
             version_row(product="Apache Tomcat", vendor="ASF")],
            [],
        )

    def tearDown(self):
        self.conn.close()

    def test_exact_name(self):
        p = find_product(self.conn, "Widget")
        self.assertEqual((p.vendor, p.name), ("Acme", "Widget"))

    def test_case_and_spaces_ignored(self):
        self.assertEqual(find_product(self.conn, "  apache TOMCAT ").name, "Apache Tomcat")

    def test_substring_does_not_match(self):
        # 'Widget' не должен находить 'Widget (MSI)' и наоборот
        self.assertEqual(find_product(self.conn, "Widget").name, "Widget")
        self.assertEqual(find_product(self.conn, "widget (msi)").name, "Widget (MSI)")
        with self.assertRaises(ProductNotFoundError):
            find_product(self.conn, "Widg")

    def test_not_found_message_and_suggestions(self):
        with self.assertRaises(ProductNotFoundError) as ctx:
            find_product(self.conn, "Apache Tomcta")
        self.assertIn("не найден", str(ctx.exception))
        self.assertIn("Apache Tomcat", ctx.exception.suggestions)

    def test_suggestions_for_partial_name(self):
        with self.assertRaises(ProductNotFoundError) as ctx:
            find_product(self.conn, "Wid")
        self.assertEqual(ctx.exception.suggestions[:1], ["Widget"])

    def test_no_suggestions_for_unrelated_name(self):
        with self.assertRaises(ProductNotFoundError) as ctx:
            find_product(self.conn, "zzzzzz")
        self.assertEqual(ctx.exception.suggestions, [])
        self.assertNotIn("Возможно", str(ctx.exception))

    def test_empty_name(self):
        for bad in ("", "   "):
            with self.assertRaises(QueryError):
                find_product(self.conn, bad)

    def test_vendor_filter(self):
        self.assertEqual(find_product(self.conn, "Widget", vendor="acme").vendor, "Acme")

    def test_vendor_mismatch_names_the_real_vendor(self):
        with self.assertRaises(ProductNotFoundError) as ctx:
            find_product(self.conn, "Widget", vendor="Globex")
        self.assertIn("Globex", str(ctx.exception))
        self.assertIn("Acme", str(ctx.exception))

    def test_same_name_at_two_vendors_is_ambiguous(self):
        conn = make_db([version_row(vendor="Acme"), version_row(vendor="Globex")], [])
        with self.assertRaises(AmbiguousProductError) as ctx:
            find_product(conn, "Widget")
        self.assertEqual(ctx.exception.vendors, ["Acme", "Globex"])
        self.assertIn("укажите вендора", str(ctx.exception))
        # с указанием вендора вопрос решается
        self.assertEqual(find_product(conn, "Widget", vendor="Globex").vendor, "Globex")
        conn.close()


# ----------------------------------------------------------------- safe_versions

class SafeVersionsTests(unittest.TestCase):
    def test_sorted_by_value_not_text(self):
        conn = make_db([version_row(v) for v in ("9.0.10", "10.0.1", "9.0.9")], [])
        self.assertEqual(safe_versions(conn, "Widget").safe, ("9.0.9", "9.0.10", "10.0.1"))
        conn.close()

    def test_latest_safe_is_the_newest_safe_not_the_newest_known(self):
        conn = make_db([version_row(v) for v in ("1.0", "2.0", "3.0")],
                       [vuln_row(start="2.5", fixed="9.0")])  # 3.0 уязвима
        result = safe_versions(conn, "Widget")
        self.assertEqual(result.safe, ("1.0", "2.0"))
        self.assertEqual(result.latest_safe, "2.0")
        self.assertEqual(result.latest_known, "3.0")
        self.assertEqual(result.total, 3)
        self.assertIsNone(result.upgrade_target)
        conn.close()

    def test_boundaries(self):
        # диапазон [2.0, 3.0): начало уязвимо, конец уже нет
        conn = make_db([version_row(v) for v in ("1.9", "2.0", "2.9", "3.0")],
                       [vuln_row(start="2.0", fixed="3.0")])
        self.assertEqual(safe_versions(conn, "Widget").safe, ("1.9", "3.0"))
        conn.close()

    def test_no_safe_versions_gives_upgrade_target(self):
        conn = make_db([version_row("1.0"), version_row("1.5")], [vuln_row(fixed="2.0")])
        result = safe_versions(conn, "Widget")
        self.assertEqual(result.safe, ())
        self.assertIsNone(result.latest_safe)
        self.assertEqual(result.latest_known, "1.5")
        self.assertEqual(result.upgrade_target, "2.0")
        conn.close()

    def test_upgrade_target_follows_chain_of_overlapping_ranges(self):
        # 1.0 -> попадает в [0, 2.0); 2.0 -> в [1.5, 4.0); 4.0 свободна
        conn = make_db([version_row("1.0")],
                       [vuln_row("KLA1", start="0", fixed="2.0"),
                        vuln_row("KLA2", start="1.5", fixed="4.0")])
        self.assertEqual(safe_versions(conn, "Widget").upgrade_target, "4.0")
        conn.close()

    def test_product_without_rules_all_safe(self):
        conn = make_db([version_row("1.0"), version_row("2.0")], [])
        result = safe_versions(conn, "Widget")
        self.assertEqual(result.safe, ("1.0", "2.0"))
        self.assertEqual(result.total, 2)
        conn.close()

    def test_product_without_versions(self):
        conn = make_db([], [vuln_row()])
        result = safe_versions(conn, "Widget")
        self.assertEqual((result.total, result.safe, result.latest_known, result.upgrade_target),
                         (0, (), None, None))
        conn.close()

    def test_empty_range_does_not_make_anything_unsafe(self):
        conn = make_db([version_row("128"), version_row("128.0.1")],
                       [vuln_row(start="128", fixed="128.0")])
        self.assertEqual(safe_versions(conn, "Widget").safe, ("128", "128.0.1"))
        conn.close()

    def test_unknown_product(self):
        conn = make_db([version_row()], [])
        with self.assertRaises(ProductNotFoundError):
            safe_versions(conn, "Nope")
        conn.close()


# ---------------------------------------------------------- vulnerabilities_for

class VulnerabilitiesForTests(unittest.TestCase):
    def test_hit_and_boundaries(self):
        conn = make_db([version_row("1.0")], [vuln_row(start="1.0", fixed="2.0")])
        for version, expected in (("0.9", False), ("1.0", True), ("1.9.9", True),
                                  ("2.0", False), ("3", False)):
            with self.subTest(version=version):
                self.assertEqual(vulnerabilities_for(conn, "Widget", version).is_vulnerable, expected)
        conn.close()

    def test_equal_values_give_equal_answers(self):
        conn = make_db([version_row("15")], [vuln_row(start="15", fixed="15.4.1")])
        a = vulnerabilities_for(conn, "Widget", "15")
        b = vulnerabilities_for(conn, "Widget", "15.0.0")
        self.assertEqual(
            [v.kla_id for v in a.vulnerabilities], [v.kla_id for v in b.vulnerabilities])
        self.assertTrue(a.is_vulnerable)
        conn.close()

    def test_report_fields(self):
        conn = make_db([version_row("1.0")], [vuln_row(date="2024-07-11", desc="Remote code execution")])
        report = vulnerabilities_for(conn, "widget", " 1.0 ")
        self.assertEqual(report.product.name, "Widget")
        self.assertEqual(report.product.vendor, "Acme")
        self.assertEqual(report.version, "1.0")
        self.assertTrue(report.in_catalog)
        v = report.vulnerabilities[0]
        self.assertEqual((v.kla_id, v.publish_date, v.description),
                         ("KLA1", "2024-07-11", "Remote code execution"))
        self.assertEqual(v.ranges, (VersionRange("0", "2.0"),))
        self.assertEqual(report.upgrade_target, "2.0")
        conn.close()

    def test_version_not_in_catalog_is_still_checked(self):
        conn = make_db([version_row("1.0")], [vuln_row(fixed="2.0")])
        report = vulnerabilities_for(conn, "Widget", "1.5")
        self.assertFalse(report.in_catalog)
        self.assertTrue(report.is_vulnerable)
        conn.close()

    def test_in_catalog_compares_by_value(self):
        conn = make_db([version_row("128.3.0")], [])
        self.assertTrue(vulnerabilities_for(conn, "Widget", "128.3").in_catalog)
        conn.close()

    def test_not_vulnerable(self):
        conn = make_db([version_row("5.0")], [vuln_row(fixed="2.0")])
        report = vulnerabilities_for(conn, "Widget", "5.0")
        self.assertFalse(report.is_vulnerable)
        self.assertEqual(report.vulnerabilities, ())
        self.assertIsNone(report.upgrade_target)
        conn.close()

    def test_invalid_version_raises(self):
        conn = make_db([version_row()], [])
        for bad in ("", "1.2.x", "v1", "abc"):
            with self.subTest(version=bad):
                with self.assertRaises(InvalidVersionError):
                    vulnerabilities_for(conn, "Widget", bad)
        conn.close()

    def test_unknown_product(self):
        conn = make_db([version_row()], [])
        with self.assertRaises(ProductNotFoundError):
            vulnerabilities_for(conn, "Nope", "1.0")
        conn.close()

    def test_one_advisory_with_several_ranges_is_one_entry(self):
        conn = make_db([version_row("1.0")], [
            vuln_row("KLA1", start="0", fixed="9.0"),
            vuln_row("KLA1", start="0", fixed="2.0"),
            vuln_row("KLA1", start="0", fixed="5.0"),
        ])
        report = vulnerabilities_for(conn, "Widget", "1.0")
        self.assertEqual(len(report.vulnerabilities), 1)
        v = report.vulnerabilities[0]
        self.assertEqual([r.fixed for r in v.ranges], ["2.0", "5.0", "9.0"])  # по возрастанию
        self.assertEqual(v.fixed_versions, ("2.0", "5.0", "9.0"))
        self.assertEqual(report.upgrade_target, "9.0")
        conn.close()

    def test_only_matching_ranges_of_an_advisory_are_listed(self):
        conn = make_db([version_row("3.0")], [
            vuln_row("KLA1", start="0", fixed="2.0"),    # 3.0 не попадает
            vuln_row("KLA1", start="3.0", fixed="3.5"),  # попадает
        ])
        v = vulnerabilities_for(conn, "Widget", "3.0").vulnerabilities[0]
        self.assertEqual(v.ranges, (VersionRange("3.0", "3.5"),))
        conn.close()

    def test_newest_advisory_first_ties_by_id(self):
        conn = make_db([version_row("1.0")], [
            vuln_row("KLA2", date="2024-01-01"),
            vuln_row("KLA9", date="2024-09-01"),
            vuln_row("KLA3", date="2024-09-01"),
        ])
        ids = [v.kla_id for v in vulnerabilities_for(conn, "Widget", "1.0").vulnerabilities]
        self.assertEqual(ids, ["KLA3", "KLA9", "KLA2"])
        conn.close()

    def test_other_products_are_not_mixed_in(self):
        conn = make_db([version_row(product="Widget"), version_row(product="Gadget")], [
            vuln_row("KLA1", product="Widget"), vuln_row("KLA2", product="Gadget")])
        ids = [v.kla_id for v in vulnerabilities_for(conn, "Gadget", "1.0").vulnerabilities]
        self.assertEqual(ids, ["KLA2"])
        conn.close()

    def test_shared_advisory_reported_for_each_product(self):
        conn = make_db([version_row(product="Widget"), version_row(product="Gadget")], [
            vuln_row("KLA1", product="Widget"), vuln_row("KLA1", product="Gadget")])
        for product in ("Widget", "Gadget"):
            report = vulnerabilities_for(conn, product, "1.0")
            self.assertEqual([v.kla_id for v in report.vulnerabilities], ["KLA1"])
        conn.close()


# ------------------------------------------------- сверка с независимым расчётом

def pad(text):
    """Независимое от versioning.py представление версии: кортеж чисел, дополненный нулями."""
    parts = tuple(int(x) for x in text.split("."))
    return parts + (0,) * (6 - len(parts))


class RealDataOracleTests(unittest.TestCase):
    """Все ответы по настоящим данным сверяются с эталоном, посчитанным прямо из JSON
    обычным сравнением кортежей (без make_key и без SQL)."""

    @classmethod
    def setUpClass(cls):
        cls.conn = connect(":memory:")
        create_schema(cls.conn)
        versions = read_json(DEFAULT_VERSIONS)
        vulns = read_json(DEFAULT_VULNS)
        load_data(cls.conn, versions, vulns)
        cls.versions = defaultdict(list)
        cls.rules = defaultdict(list)
        for r in versions:
            cls.versions[r["product"]].append(r["version"])
        for r in vulns:
            cls.rules[r["product"]].append(r)

    @classmethod
    def tearDownClass(cls):
        cls.conn.close()

    @staticmethod
    def hit(rule, version):
        return pad(rule["start_vuln_version"]) <= pad(version) < pad(rule["fixed_version"])

    def test_safe_versions_for_every_product(self):
        for product, versions in self.versions.items():
            with self.subTest(product=product):
                expected = sorted(
                    (v for v in versions if not any(self.hit(r, v) for r in self.rules[product])),
                    key=lambda v: (pad(v), v))
                self.assertEqual(list(safe_versions(self.conn, product).safe), expected)

    def test_vulnerabilities_for_every_catalog_version(self):
        checked = 0
        for product, versions in self.versions.items():
            for version in versions:
                matching = [r for r in self.rules[product] if self.hit(r, version)]
                report = vulnerabilities_for(self.conn, product, version)
                with self.subTest(product=product, version=version):
                    self.assertEqual({v.kla_id for v in report.vulnerabilities},
                                     {r["KLA_id"] for r in matching})
                    # все сработавшие строки фида учтены ровно один раз
                    got = sorted((v.kla_id, r.start, r.fixed)
                                 for v in report.vulnerabilities for r in v.ranges)
                    want = sorted((r["KLA_id"], r["start_vuln_version"], r["fixed_version"])
                                  for r in matching)
                    self.assertEqual(got, want)
                    self.assertTrue(report.in_catalog)
                    self.assertEqual(report.is_vulnerable, bool(matching))
                    self.assertEqual(report.upgrade_target is not None, bool(matching))
                checked += 1
        self.assertEqual(checked, 834)

    def test_upgrade_target_is_the_smallest_uncovered_version(self):
        """Цель обновления не уязвима, а любая известная граница между версией и целью покрыта."""
        for product, versions in self.versions.items():
            rules = self.rules[product]
            boundaries = sorted({pad(r["fixed_version"]) for r in rules})
            for version in versions:
                report = vulnerabilities_for(self.conn, product, version)
                if not report.is_vulnerable:
                    continue
                target = pad(report.upgrade_target)
                with self.subTest(product=product, version=version):
                    covered = lambda x: any(
                        pad(r["start_vuln_version"]) <= x < pad(r["fixed_version"]) for r in rules)
                    self.assertGreater(target, pad(version))
                    self.assertFalse(covered(target))
                    # наименьшая непокрытая точка выше версии -- одна из исправленных версий
                    expected = min(b for b in boundaries if b > pad(version) and not covered(b))
                    self.assertEqual(target, expected)

    def test_known_answers(self):
        c = self.conn
        tomcat = safe_versions(c, "Apache Tomcat")
        self.assertEqual((tomcat.total, tomcat.safe, tomcat.latest_safe),
                         (226, ("9.0.98", "10.0.27"), "10.0.27"))
        self.assertEqual(safe_versions(c, "Mozilla Thunderbird").safe, ("133.0",))
        self.assertEqual(len(safe_versions(c, "KeePass Password Safe").safe), 44)
        ultra = safe_versions(c, "UltraISO")
        self.assertEqual((ultra.total, len(ultra.safe), ultra.latest_safe), (8, 8, "9.76"))

    def test_product_without_safe_versions(self):
        vbox = safe_versions(self.conn, "Oracle VirtualBox")
        self.assertEqual((vbox.total, vbox.safe, vbox.latest_safe), (14, (), None))
        self.assertEqual(vbox.latest_known, "7.1.4")
        self.assertEqual(vbox.upgrade_target, "7.1.6")

    def test_advisory_with_many_ranges_is_listed_once(self):
        # KLA67449 (Git for Windows) состоит из 7 строк фида
        report = vulnerabilities_for(self.conn, "Git for Windows", "2.19.2")
        git = [v for v in report.vulnerabilities if v.kla_id == "KLA67449"]
        self.assertEqual(len(git), 1)
        self.assertEqual(len(git[0].ranges), 7)
        self.assertEqual(git[0].fixed_versions[0], "2.39.4")
        self.assertEqual(git[0].fixed_versions[-1], "2.45.1")

    def test_empty_range_advisory_never_reported(self):
        for product in self.versions:
            for version in self.versions[product]:
                report = vulnerabilities_for(self.conn, product, version)
                self.assertNotIn("KLA70478", {
                    v.kla_id for v in report.vulnerabilities
                    if any(r.start == "128" and r.fixed == "128.0" for r in v.ranges)})

    def test_vendor_filter_on_real_data(self):
        self.assertEqual(safe_versions(self.conn, "PuTTY", vendor="Simon Tatham").product.vendor,
                         "Simon Tatham")
        with self.assertRaises(ProductNotFoundError):
            safe_versions(self.conn, "PuTTY", vendor="Google")

    def test_suggestions_on_real_data(self):
        with self.assertRaises(ProductNotFoundError) as ctx:
            safe_versions(self.conn, "VLC")
        self.assertEqual(ctx.exception.suggestions[:2],
                         ["VLC media player", "VLC media player (MSI installer)"])
        with self.assertRaises(ProductNotFoundError) as ctx:
            safe_versions(self.conn, "Tomcta")
        self.assertIn("Apache Tomcat", ctx.exception.suggestions)

    def test_both_vlc_products_are_distinct(self):
        self.assertEqual(safe_versions(self.conn, "vlc media player").product.name, "VLC media player")
        self.assertEqual(safe_versions(self.conn, "VLC media player (MSI installer)").product.name,
                         "VLC media player (MSI installer)")


class ReadOnlyDatabaseTests(unittest.TestCase):
    def test_queries_work_on_readonly_file_with_unicode_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "Папка с пробелом"
            db = folder / "база.db"
            load_files(db, DEFAULT_VERSIONS, DEFAULT_VULNS)
            conn = connect_readonly(db)
            try:
                self.assertEqual(safe_versions(conn, "Apache Tomcat").latest_safe, "10.0.27")
                self.assertTrue(vulnerabilities_for(conn, "Apache Tomcat", "9.0.50").is_vulnerable)
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main()
