"""
sigma_engine.py - a minimal, dependency-light Sigma rule evaluator.

Why build our own instead of only relying on a SIEM?
  * Lets CI *execute* every rule against sample telemetry offline,
    with zero SIEM required -> real unit tests for detections.
  * Keeps matching semantics transparent and auditable.

Supported Sigma features
  * Selections as maps (AND across fields) or lists of maps (OR)
  * Value lists (OR) and the |all modifier (AND)
  * Modifiers: contains, startswith, endswith, re, all, cased, exists
  * Wildcards * and ? in plain values
  * null values (field must be absent/empty)
  * Conditions: and / or / not / parentheses,
    "1 of <pattern>", "all of <pattern>", "1 of them", "all of them"
"""
from __future__ import annotations

import fnmatch
import re
from typing import Any

SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "re", "all", "cased", "exists"}


class SigmaError(Exception):
    """Raised when a rule uses unsupported or malformed syntax."""


# --------------------------------------------------------------------------- #
# Field / value matching
# --------------------------------------------------------------------------- #
def _get_field(event: dict, field: str) -> Any:
    """Case-insensitive field lookup with dotted-path support."""
    if field in event:
        return event[field]
    for k, v in event.items():
        if k.lower() == field.lower():
            return v
    cur: Any = event
    for part in field.split("."):
        if not isinstance(cur, dict):
            return None
        nxt = None
        for k, v in cur.items():
            if k.lower() == part.lower():
                nxt = v
                break
        if nxt is None:
            return None
        cur = nxt
    return cur


def _match_single(actual: Any, expected: Any, mods: list[str]) -> bool:
    if "exists" in mods:
        present = actual is not None and actual != ""
        return present == bool(expected)

    if expected is None:
        return actual is None or actual == ""
    if actual is None:
        return False

    cased = "cased" in mods
    a, e = str(actual), str(expected)

    if "re" in mods:
        return re.search(e, a, 0 if cased else re.IGNORECASE) is not None

    if not cased:
        a, e = a.lower(), e.lower()

    if "contains" in mods:
        return e in a
    if "startswith" in mods:
        return a.startswith(e)
    if "endswith" in mods:
        return a.endswith(e)

    # Plain equality, with Sigma wildcard support
    if "*" in e or "?" in e:
        return fnmatch.fnmatchcase(a, e)
    return a == e


def _match_field(event: dict, key: str, expected: Any) -> bool:
    field, *mods = key.split("|")
    unknown = set(mods) - SUPPORTED_MODIFIERS
    if unknown:
        raise SigmaError(f"Unsupported modifier(s) {sorted(unknown)} on field '{field}'")

    actual = _get_field(event, field)
    values = expected if isinstance(expected, list) else [expected]
    actual_values = actual if isinstance(actual, list) else [actual]

    def one(v: Any) -> bool:
        return any(_match_single(av, v, mods) for av in actual_values)

    return all(one(v) for v in values) if "all" in mods else any(one(v) for v in values)


def _match_selection(event: dict, selection: Any) -> bool:
    if isinstance(selection, dict):
        return all(_match_field(event, k, v) for k, v in selection.items())
    if isinstance(selection, list):
        if all(isinstance(s, dict) for s in selection):      # list of maps -> OR
            return any(_match_selection(event, s) for s in selection)
        blob = " ".join(str(v) for v in event.values()).lower()  # keywords
        return any(str(s).lower() in blob for s in selection)
    raise SigmaError(f"Invalid selection type: {type(selection).__name__}")


# --------------------------------------------------------------------------- #
# Condition parsing (recursive descent)
#   expr   := term ( 'or' term )*
#   term   := factor ( 'and' factor )*
#   factor := 'not' factor | '(' expr ')' | quant | IDENT
#   quant  := ('1'|'all') 'of' (PATTERN | 'them')
# --------------------------------------------------------------------------- #
_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_\*]+)")


def tokenize(condition: str) -> list[str]:
    pos, tokens = 0, []
    condition = condition.strip()
    while pos < len(condition):
        m = _TOKEN.match(condition, pos)
        if not m:
            raise SigmaError(f"Cannot parse condition near: {condition[pos:]!r}")
        tokens.append(m.group(1))
        pos = m.end()
    return tokens


def selection_names(detection: dict) -> list[str]:
    return [k for k in detection if k not in ("condition", "timeframe")]


def resolve_pattern(detection: dict, target: str) -> list[str]:
    names = selection_names(detection)
    if target.lower() == "them":
        return names
    found = [n for n in names if fnmatch.fnmatchcase(n, target)]
    if not found:
        raise SigmaError(f"No selections match pattern '{target}'")
    return found


class _Parser:
    def __init__(self, tokens: list[str], detection: dict, event: dict):
        self.t, self.i = tokens, 0
        self.det = detection
        self.event = event

    def peek(self) -> str | None:
        return self.t[self.i].lower() if self.i < len(self.t) else None

    def take(self) -> str:
        if self.i >= len(self.t):
            raise SigmaError("Unexpected end of condition")
        tok = self.t[self.i]
        self.i += 1
        return tok

    def parse(self) -> bool:
        result = self.expr()
        if self.i != len(self.t):
            raise SigmaError(f"Unexpected token: {self.t[self.i]!r}")
        return result

    def expr(self) -> bool:
        val = self.term()
        while self.peek() == "or":
            self.take()
            rhs = self.term()          # always evaluate -> full syntax validation
            val = val or rhs
        return val

    def term(self) -> bool:
        val = self.factor()
        while self.peek() == "and":
            self.take()
            rhs = self.factor()
            val = val and rhs
        return val

    def factor(self) -> bool:
        tok = self.peek()
        if tok is None:
            raise SigmaError("Unexpected end of condition")
        if tok == "not":
            self.take()
            return not self.factor()
        if tok == "(":
            self.take()
            val = self.expr()
            if self.peek() != ")":
                raise SigmaError("Missing closing parenthesis")
            self.take()
            return val
        if tok in ("1", "all") and self.i + 1 < len(self.t) and self.t[self.i + 1].lower() == "of":
            quant = self.take().lower()
            self.take()  # 'of'
            names = resolve_pattern(self.det, self.take())
            results = [_match_selection(self.event, self.det[n]) for n in names]
            return all(results) if quant == "all" else any(results)
        name = self.take()
        if name not in self.det or name in ("condition", "timeframe"):
            raise SigmaError(f"Condition references unknown selection '{name}'")
        return _match_selection(self.event, self.det[name])


def matches(rule: dict, event: dict) -> bool:
    """Return True if `event` satisfies the Sigma `rule`."""
    detection = rule.get("detection") or {}
    condition = detection.get("condition")
    if not condition:
        raise SigmaError("Rule has no detection.condition")
    conditions = condition if isinstance(condition, list) else [condition]
    return any(_Parser(tokenize(c), detection, event).parse() for c in conditions)
