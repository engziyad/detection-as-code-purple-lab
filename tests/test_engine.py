"""Unit tests for the Sigma engine and converter themselves (python -m unittest)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
from sigma_engine import SigmaError, matches  # noqa: E402
from convert import convert  # noqa: E402


def rule(detection, category="process_creation"):
    return {"title": "t", "id": "x", "logsource": {"product": "windows", "category": category},
            "detection": detection}


class EngineModifiers(unittest.TestCase):
    def test_contains_case_insensitive(self):
        r = rule({"s": {"CommandLine|contains": "MIMIKATZ"}, "condition": "s"})
        self.assertTrue(matches(r, {"CommandLine": "run mimikatz.exe"}))

    def test_cased(self):
        r = rule({"s": {"CommandLine|contains|cased": "ABC"}, "condition": "s"})
        self.assertFalse(matches(r, {"CommandLine": "abc"}))

    def test_startswith_endswith(self):
        r = rule({"s": {"Image|startswith": "C:\\Users\\", "Image|endswith": ".exe"}, "condition": "s"})
        self.assertTrue(matches(r, {"Image": "C:\\Users\\a\\x.exe"}))
        self.assertFalse(matches(r, {"Image": "C:\\Windows\\x.exe"}))

    def test_all_modifier(self):
        r = rule({"s": {"CommandLine|contains|all": ["a", "b"]}, "condition": "s"})
        self.assertTrue(matches(r, {"CommandLine": "a b"}))
        self.assertFalse(matches(r, {"CommandLine": "a"}))

    def test_wildcard(self):
        r = rule({"s": {"Image": "*\\cmd.exe"}, "condition": "s"})
        self.assertTrue(matches(r, {"Image": "C:\\Windows\\System32\\cmd.exe"}))

    def test_null_and_exists(self):
        r = rule({"s": {"ParentImage": None}, "condition": "s"})
        self.assertTrue(matches(r, {"Image": "x"}))
        r = rule({"s": {"ParentImage|exists": True}, "condition": "s"})
        self.assertFalse(matches(r, {"Image": "x"}))

    def test_numeric_equality(self):
        r = rule({"s": {"EventID": 4769}, "condition": "s"})
        self.assertTrue(matches(r, {"EventID": "4769"}))

    def test_missing_field_does_not_match(self):
        r = rule({"s": {"CommandLine|contains": "x"}, "condition": "s"})
        self.assertFalse(matches(r, {}))


class EngineConditions(unittest.TestCase):
    det = {"a": {"X": "1"}, "b": {"Y": "1"}, "f_1": {"Z": "1"}, "f_2": {"W": "1"}}

    def eval(self, cond, ev):
        return matches(rule({**self.det, "condition": cond}), ev)

    def test_precedence_and_binds_tighter(self):
        self.assertTrue(self.eval("a or b and f_1", {"X": "1"}))
        self.assertFalse(self.eval("(a or b) and f_1", {"X": "1"}))

    def test_not_and_quantifiers(self):
        self.assertTrue(self.eval("a and not 1 of f_*", {"X": "1"}))
        self.assertFalse(self.eval("a and not 1 of f_*", {"X": "1", "W": "1"}))
        self.assertTrue(self.eval("all of f_*", {"Z": "1", "W": "1"}))
        self.assertTrue(self.eval("1 of them", {"Y": "1"}))

    def test_errors(self):
        with self.assertRaises(SigmaError):
            self.eval("a and missing", {})
        with self.assertRaises(SigmaError):
            self.eval("(a or b", {})
        with self.assertRaises(SigmaError):
            matches(rule({"s": {"X|base64offset": "a"}, "condition": "s"}), {"X": "a"})


class Converter(unittest.TestCase):
    def test_kql_and_spl_render(self):
        r = rule({"sel": {"Image|endswith": "\\rundll32.exe"}, "f": {"User": "SYSTEM"},
                  "condition": "sel and not f"})
        kql = convert(r, "kql")
        spl = convert(r, "spl")
        self.assertIn('Image endswith @"\\rundll32.exe"', kql)
        self.assertIn("not(", kql)
        self.assertIn("NOT (", spl)
        self.assertIn("EventCode=1", spl)


if __name__ == "__main__":
    unittest.main()
