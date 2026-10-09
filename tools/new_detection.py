#!/usr/bin/env python3
"""
new_detection.py - scaffold a new detection folder that already passes the linter's
structure checks, so contributors only write the logic, tests and notes.

Usage
  python tools/new_detection.py T1110.003 password_spraying
"""
from __future__ import annotations

import datetime as dt
import re
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

RULE = """title: TODO - short, specific title
id: {id}
status: experimental
description: |
  TODO - what behaviour this detects and why it matters.
references:
  - https://attack.mitre.org/techniques/{tech_path}/
author: Ziyad (github.com/engziyad)
date: {date}
tags:
  - attack.TODO-tactic
  - attack.{tech_tag}
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\TODO.exe'
  condition: selection
falsepositives:
  - TODO
level: medium
"""

README = """# TODO - detection title

## Telemetry required
## How the detection works
## Evasion & coverage gaps (purple-team notes)
## False positives & tuning
## SOC triage playbook
## Emulation
"""


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 1
    tech, name = sys.argv[1].upper(), sys.argv[2].lower()
    if not re.match(r"^T\d{4}(\.\d{3})?$", tech) or not re.match(r"^[a-z0-9_]+$", name):
        print("Usage: new_detection.py T1234.001 snake_case_name")
        return 1
    folder = ROOT / "detections" / f"{tech}_{name}"
    if folder.exists():
        print(f"{folder} already exists")
        return 1
    (folder / "tests").mkdir(parents=True)
    (folder / "rule.yml").write_text(RULE.format(
        id=uuid.uuid4(), date=dt.date.today().isoformat(),
        tech_path=tech.replace(".", "/"), tech_tag=tech.lower()), encoding="utf-8")
    (folder / "README.md").write_text(README, encoding="utf-8")
    (folder / "tests" / "true_positive.jsonl").write_text(
        '{"_case": "TODO malicious example", "EventID": 1, "Image": "C:\\\\TODO.exe"}\n', encoding="utf-8")
    (folder / "tests" / "true_negative.jsonl").write_text(
        '{"_case": "TODO benign example", "EventID": 1, "Image": "C:\\\\Windows\\\\explorer.exe"}\n', encoding="utf-8")
    print(f"[+] scaffolded {folder.relative_to(ROOT)} - now edit rule.yml, tests and README.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
