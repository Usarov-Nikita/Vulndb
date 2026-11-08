import json
import unittest
from pathlib import Path

from vulndb.versioning import (
    COMPONENT_WIDTH,
    MAX_PARTS,
    InvalidVersionError,
    make_key,
    parse_version,
)

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


class ParseVersionTests(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(parse_version("2"), (2,))
        self.assertEqual(parse_version("7.1"), (7, 1))
        self.assertEqual(parse_version("9.0.10"), (9, 0, 10))
        self.assertEqual(parse_version("132.0.6834.83"), (132, 0, 6834, 83))

    def test_leading_zeros_are_numeric(self):
        # реальный формат из данных: Adobe Acrobat Reader
        self.assertEqual(parse_version("20.005.30514"), (20, 5, 30514))
        self.assertEqual(parse_version("24.09"), (24, 9))

    def test_surrounding_whitespace_is_ignored(self):
        self.assertEqual(parse_version("  1.2.3\n"), (1, 2, 3))

    def test_invalid_inputs(self):
        bad = ["", " ", ".", "1.", ".1", "1..2", "1.2.x", "v1.0", "-1", "1.-2",
               "1,2", "1.2-beta", "abc", "١.٢"]  # последняя -- арабо-индийские цифры
        for text in bad:
            with self.subTest(text=text):
                with self.assertRaises(InvalidVersionError):
                    parse_version(text)

    def test_non_string(self):
        for value in (None, 1, 1.5, ("1", "2")):
            with self.subTest(value=value):
                with self.assertRaises(InvalidVersionError):
                    parse_version(value)

    def test_too_many_parts(self):
        ok = ".".join(["1"] * MAX_PARTS)
        too_many = ".".join(["1"] * (MAX_PARTS + 1))
        self.assertEqual(len(parse_version(ok)), MAX_PARTS)
        with self.assertRaises(InvalidVersionError):
            parse_version(too_many)

    def test_component_too_long(self):
        ok = "1." + "9" * COMPONENT_WIDTH
        too_long = "1." + "9" * (COMPONENT_WIDTH + 1)
        parse_version(ok)
        with self.assertRaises(InvalidVersionError):
            parse_version(too_long)


class MakeKeyTests(unittest.TestCase):
    def test_numeric_not_lexicographic(self):
        # ловушка: как строки "10.0.1" < "9.0.9"
        self.assertLess(make_key("9.0.9"), make_key("9.0.10"))
        self.assertLess(make_key("9.0.10"), make_key("10.0.1"))
        self.assertGreater("9.0.9", "10.0.1")  # строковое сравнение ошибается

    def test_missing_components_are_zeros(self):
        self.assertEqual(make_key("15"), make_key("15.0.0"))
        self.assertEqual(make_key("7.1"), make_key("7.1.0.0"))

    def test_zero_is_smallest(self):
        # start_vuln_version = "0" означает «с самого начала»
        for v in ("0.0.1", "0.82", "1", "2.4"):
            with self.subTest(v=v):
                self.assertLess(make_key("0"), make_key(v))

    def test_trailing_nonzero_matters(self):
        self.assertLess(make_key("15.0"), make_key("15.0.1"))
        self.assertLess(make_key("15.4.1"), make_key("15.4.1.1"))

    def test_fixed_boundary_semantics(self):
        # диапазон [start, fixed): fixed сам НЕ уязвим
        start, fixed = make_key("15"), make_key("15.4.1")
        self.assertTrue(start <= make_key("15.4") < fixed)
        self.assertFalse(start <= make_key("15.4.1") < fixed)
        self.assertFalse(start <= make_key("16.0") < fixed)
        self.assertFalse(start <= make_key("14.9") < fixed)

    def test_key_has_fixed_length(self):
        expected = MAX_PARTS * COMPONENT_WIDTH + (MAX_PARTS - 1)
        for v in ("0", "1.2", "132.0.6834.83"):
            self.assertEqual(len(make_key(v)), expected)

    def test_key_error_propagates(self):
        with self.assertRaises(InvalidVersionError):
            make_key("1.2.x")


class RealDataTests(unittest.TestCase):
    """Проверка на реальных фидах: ключ должен упорядочивать так же, как кортежи."""

    @classmethod
    def setUpClass(cls):
        cls.versions = json.loads((DATA_DIR / "versions.json").read_text(encoding="utf-8"))
        cls.vulns = json.loads((DATA_DIR / "vulnerabilities.json").read_text(encoding="utf-8"))

    def test_every_version_in_both_feeds_parses(self):
        texts = [r["version"] for r in self.versions]
        texts += [r["start_vuln_version"] for r in self.vulns]
        texts += [r["fixed_version"] for r in self.vulns]
        for t in texts:
            with self.subTest(version=t):
                make_key(t)

    def test_key_order_equals_tuple_order(self):
        texts = sorted({r["version"] for r in self.versions}
                       | {r["fixed_version"] for r in self.vulns}
                       | {r["start_vuln_version"] for r in self.vulns})

        def padded(t):
            p = parse_version(t)
            return p + (0,) * (MAX_PARTS - len(p))

        self.assertEqual(sorted(texts, key=make_key), sorted(texts, key=padded))

    def test_no_inverted_ranges(self):
        # start > fixed было бы ошибкой в данных
        for r in self.vulns:
            with self.subTest(kla=r["KLA_id"], product=r["product"]):
                self.assertLessEqual(make_key(r["start_vuln_version"]), make_key(r["fixed_version"]))

    def test_known_empty_range(self):
        # Запись "128 -> 128.0" (KLA70478, Thunderbird): 128 == 128.0,
        # значит интервал [128, 128.0) пуст и под него не попадает ни одна версия.
        # Это единственный такой случай; schema.sql должна допускать start_key <= fixed_key,
        # а загрузчик -- предупреждать о пустых интервалах.
        empty = [
            (r["KLA_id"], r["start_vuln_version"], r["fixed_version"])
            for r in self.vulns
            if make_key(r["start_vuln_version"]) == make_key(r["fixed_version"])
        ]
        self.assertEqual(empty, [("KLA70478", "128", "128.0")])


if __name__ == "__main__":
    unittest.main()
