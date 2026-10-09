#!/usr/bin/env python3
"""
validate.py - quality gate for every detection (runs before unit tests).

Checks
  * required metadata (title, UUID id, status, level, author, date, ...)
  * ATT&CK tags present and folder name matches a tagged technique
  * unique rule IDs across the repository
  * condition parses and only references existing selections
  * logsource has a mapping for every SIEM backend
  * every detection ships a README plus true-positive AND true-negative tests
"""
from __future__ import annotations

import re
import sys
import uuid
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sigma_engine import SigmaError, matches  # noqa: E402
from convert import BACKENDS, MAPPINGS, logsource_key  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
REQUIRED = ["title", "id", "status", "description", "author", "date",
            "tags", "logsource", "detection", "falsepositives", "level"]
STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}
LEVELS = {"informational", "low", "medium", "high", "critical"}
TECH_TAG = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")
FOLDER = re.compile(r"^(T\d{4}(?:\.\d{3})?)_[a-z0-9_]+$")


def check(folder: Path, seen_ids: dict) -> list[str]:
    errs: list[str] = []
    rule_path = folder / "rule.yml"
    if not rule_path.exists():
        return ["missing rule.yml"]
    try:
        rule = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        return [f"YAML error: {e}"]

    errs += [f"missing field '{k}'" for k in REQUIRED if k not in rule]
    if "TODO" in rule_path.read_text(encoding="utf-8"):
        errs.append("rule.yml still contains TODO placeholders")

    try:
        uuid.UUID(str(rule.get("id")))
    except ValueError:
        errs.append("id is not a valid UUID")
    rid = str(rule.get("id"))
    if rid in seen_ids:
        errs.append(f"duplicate id (also used by {seen_ids[rid]})")
    seen_ids[rid] = folder.name

    if rule.get("status") not in STATUSES:
        errs.append(f"invalid status '{rule.get('status')}'")
    if rule.get("level") not in LEVELS:
        errs.append(f"invalid level '{rule.get('level')}'")
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", str(rule.get("date", ""))):
        errs.append("date must be YYYY-MM-DD")

    techniques = [t for t in rule.get("tags", []) if TECH_TAG.match(t)]
    if not techniques:
        errs.append("no ATT&CK technique tag (attack.tXXXX)")
    m = FOLDER.match(folder.name)
    if not m:
        errs.append("folder must be named <TechniqueID>_<snake_case_name>")
    elif f"attack.{m.group(1).lower()}" not in techniques:
        errs.append(f"folder technique {m.group(1)} not present in tags")

    # Condition must parse and reference real selections (evaluate on empty event)
    try:
        matches(rule, {})
    except SigmaError as e:
        errs.append(f"detection logic: {e}")

    key = logsource_key(rule)
    for b in BACKENDS:
        if key not in MAPPINGS[b]["logsources"]:
            errs.append(f"logsource '{key}' has no {b} mapping in tools/mappings.yml")

    readme = folder / "README.md"
    if not readme.exists():
        errs.append("missing README.md (detection documentation)")
    elif "TODO" in readme.read_text(encoding="utf-8"):
        errs.append("README.md still contains TODO placeholders")
    for kind in ("true_positive", "true_negative"):
        p = folder / "tests" / f"{kind}.jsonl"
        if not p.exists() or not p.read_text(encoding="utf-8").strip():
            errs.append(f"missing or empty tests/{kind}.jsonl")
    return errs


def main() -> int:
    folders = sorted(p for p in (ROOT / "detections").iterdir() if p.is_dir())
    seen: dict = {}
    failed = 0
    for f in folders:
        errs = check(f, seen)
        if errs:
            failed += 1
            print(f"[FAIL] {f.name}")
            for e in errs:
                print(f"         - {e}")
        else:
            print(f"[ OK ] {f.name}")
    print(f"\n{len(folders) - failed}/{len(folders)} detections valid")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
