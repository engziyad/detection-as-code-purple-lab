#!/usr/bin/env python3
"""
convert.py - translate the lab's Sigma rules into SIEM queries.

Backends
  kql : Microsoft Sentinel / Defender (Kusto Query Language)
  spl : Splunk (Search Processing Language)

Field names and base tables come from tools/mappings.yml, so the same
rule can be retargeted to any environment by editing one file.

Usage
  python tools/convert.py --backend kql                 # print all
  python tools/convert.py --backend spl --rule detections/T1059.001_*/rule.yml
  python tools/convert.py --all --out queries/          # write files
"""
from __future__ import annotations

import argparse
import glob
import os
import re
import sys
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sigma_engine import SigmaError, SUPPORTED_MODIFIERS, resolve_pattern, tokenize  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
MAPPINGS = yaml.safe_load((ROOT / "tools" / "mappings.yml").read_text(encoding="utf-8"))


def logsource_key(rule: dict) -> str:
    ls = rule.get("logsource", {})
    return ls.get("category") or f"{ls.get('product', '')}/{ls.get('service', '')}"


def wildcard_to_regex(value: str) -> str:
    return "^" + re.escape(value).replace(r"\*", ".*").replace(r"\?", ".") + "$"


# --------------------------------------------------------------------------- #
# Backends: each turns (field, modifiers, value) into one predicate string
# --------------------------------------------------------------------------- #
class KQL:
    name = "kql"
    AND, OR = "and", "or"

    @staticmethod
    def negate(x: str) -> str:
        return f"not({x})"

    @staticmethod
    def s(v: Any) -> str:                       # verbatim string literal
        return '@"' + str(v).replace('"', '""') + '"'

    def predicate(self, f: str, mods: list[str], v: Any) -> str:
        if "exists" in mods:
            return f"isnotempty({f})" if v else f"isempty({f})"
        if v is None:
            return f"isempty({f})"
        if "re" in mods:
            prefix = "" if "cased" in mods else "(?i)"
            return f"{f} matches regex {self.s(prefix + str(v))}"
        cs = "cased" in mods
        if "contains" in mods:
            return f"{f} {'contains_cs' if cs else 'contains'} {self.s(v)}"
        if "startswith" in mods:
            return f"{f} {'startswith_cs' if cs else 'startswith'} {self.s(v)}"
        if "endswith" in mods:
            return f"{f} {'endswith_cs' if cs else 'endswith'} {self.s(v)}"
        if isinstance(v, str) and ("*" in v or "?" in v):
            return f"{f} matches regex {self.s('(?i)' + wildcard_to_regex(v))}"
        if isinstance(v, (int, float)):
            return f"{f} == {v}"
        return f"{f} {'==' if cs else '=~'} {self.s(v)}"

    @staticmethod
    def wrap(base: str, where: str) -> str:
        return f"{base}\n| where {where}"


class SPL:
    name = "spl"
    AND, OR = "AND", "OR"

    @staticmethod
    def negate(x: str) -> str:
        return f"NOT {x if x.startswith('(') else '(' + x + ')'}"

    @staticmethod
    def s(v: Any) -> str:
        return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'

    def predicate(self, f: str, mods: list[str], v: Any) -> str:
        if "exists" in mods:
            return f"isnotnull('{f}')" if v else f"isnull('{f}')"
        if v is None:
            return f"isnull('{f}')"
        flag = "" if "cased" in mods else "(?i)"
        if "re" in mods:
            return f"match('{f}', {self.s(flag + str(v))})"
        if isinstance(v, (int, float)):
            return f"'{f}'={v}"
        # contains/startswith/endswith/wildcards -> anchored regex (robust with backslashes)
        if "contains" in mods:
            rx = re.escape(str(v))
        elif "startswith" in mods:
            rx = "^" + re.escape(str(v))
        elif "endswith" in mods:
            rx = re.escape(str(v)) + "$"
        elif "*" in str(v) or "?" in str(v):
            rx = wildcard_to_regex(str(v))
        else:
            if "cased" in mods:
                return f"'{f}'={self.s(v)}"
            return f"lower('{f}')={self.s(str(v).lower())}"
        return f"match('{f}', {self.s(flag + rx)})"

    @staticmethod
    def wrap(base: str, where: str) -> str:
        return f"{base}\n| where {where}"


BACKENDS = {"kql": KQL(), "spl": SPL()}


# --------------------------------------------------------------------------- #
# Generic translation of selections + condition
# --------------------------------------------------------------------------- #
def _join(parts: list[str], op: str) -> str:
    parts = [p for p in parts if p]
    if len(parts) == 1:
        return parts[0]
    return "(" + f" {op} ".join(parts) + ")"


def translate_selection(sel: Any, backend, fieldmap: dict) -> str:
    if isinstance(sel, list):
        if not all(isinstance(s, dict) for s in sel):
            raise SigmaError("Keyword selections are not supported by the converter")
        return _join([translate_selection(s, backend, fieldmap) for s in sel], backend.OR)
    clauses = []
    for key, value in sel.items():
        field, *mods = key.split("|")
        if set(mods) - SUPPORTED_MODIFIERS:
            raise SigmaError(f"Unsupported modifier on {field}")
        field = fieldmap.get(field, field)
        values = value if isinstance(value, list) else [value]
        preds = [backend.predicate(field, mods, v) for v in values]
        clauses.append(_join(preds, backend.AND if "all" in mods else backend.OR))
    return _join(clauses, backend.AND)


class _CondTranslator:
    """Recursive-descent translator mirroring sigma_engine's grammar."""

    def __init__(self, tokens, detection, backend, fieldmap):
        self.t, self.i = tokens, 0
        self.det, self.b, self.fm = detection, backend, fieldmap

    def peek(self):
        return self.t[self.i].lower() if self.i < len(self.t) else None

    def take(self):
        tok = self.t[self.i]
        self.i += 1
        return tok

    def expr(self):
        parts = [self.term()]
        while self.peek() == "or":
            self.take()
            parts.append(self.term())
        return _join(parts, self.b.OR)

    def term(self):
        parts = [self.factor()]
        while self.peek() == "and":
            self.take()
            parts.append(self.factor())
        return _join(parts, self.b.AND)

    def factor(self):
        tok = self.peek()
        if tok == "not":
            self.take()
            return self.b.negate(self.factor())
        if tok == "(":
            self.take()
            val = self.expr()
            self.take()  # ')'
            return val
        if tok in ("1", "all") and self.i + 1 < len(self.t) and self.t[self.i + 1].lower() == "of":
            quant = self.take().lower()
            self.take()
            names = resolve_pattern(self.det, self.take())
            subs = [translate_selection(self.det[n], self.b, self.fm) for n in names]
            return _join(subs, self.b.AND if quant == "all" else self.b.OR)
        return translate_selection(self.det[self.take()], self.b, self.fm)


def translate_condition(detection: dict, backend, fieldmap: dict) -> str:
    cond = detection["condition"]
    conds = cond if isinstance(cond, list) else [cond]
    return _join([_CondTranslator(tokenize(c), detection, backend, fieldmap).expr() for c in conds], backend.OR)


def convert(rule: dict, backend_name: str) -> str:
    backend = BACKENDS[backend_name]
    m = MAPPINGS[backend_name]
    key = logsource_key(rule)
    if key not in m["logsources"]:
        raise SigmaError(f"No {backend_name} mapping for logsource '{key}'")
    base = m["logsources"][key].strip()
    where = translate_condition(rule["detection"], backend, m.get("fields", {}))
    if backend_name == "kql":
        title = f"// {rule['title']} | {rule['id']}"
    else:
        title = f"``` {rule['title']} | {rule['id']} ```"
    return f"{title}\n{backend.wrap(base, where)}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--backend", choices=BACKENDS, default="kql")
    ap.add_argument("--rule", help="glob of rule files (default: all)")
    ap.add_argument("--all", action="store_true", help="generate every backend")
    ap.add_argument("--out", help="write queries to this directory instead of stdout")
    args = ap.parse_args()

    files = sorted(glob.glob(args.rule or str(ROOT / "detections" / "*" / "rule.yml")))
    backends = list(BACKENDS) if args.all else [args.backend]
    failed = 0
    for path in files:
        rule = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        folder = Path(path).parent.name
        for b in backends:
            try:
                q = convert(rule, b)
            except SigmaError as e:
                print(f"[!] {folder} ({b}): {e}", file=sys.stderr)
                failed += 1
                continue
            if args.out:
                os.makedirs(Path(args.out) / b, exist_ok=True)
                ext = "kql" if b == "kql" else "spl"
                (Path(args.out) / b / f"{folder}.{ext}").write_text(q + "\n", encoding="utf-8")
            else:
                print(q, end="\n\n")
    if args.out:
        print(f"[+] wrote {len(files) * len(backends) - failed} queries to {args.out}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
