# Writing Detections

## Quality bar

A detection is merged only when **all** of the following are true:

- [ ] It targets a **behaviour**, not a single tool name, hash or IP.
- [ ] It has at least one `true_positive` sample taken from real emulation (or faithfully reconstructed from it).
- [ ] It has `true_negative` samples representing the **closest benign activity** you can find, not unrelated events.
- [ ] Every filter is justified by a true-negative test case.
- [ ] Its README documents telemetry, logic, **evasion gaps**, tuning and triage.
- [ ] `make ci` passes.

## Conventions

| Item | Convention |
|---|---|
| Folder | `<TechniqueID>_<snake_case_name>`, e.g. `T1003.001_lsass_memory_access` |
| Rule ID | Random UUIDv4, never reused |
| Tags | Tactic tags plus at least one `attack.tXXXX` tag matching the folder |
| Status | `experimental` → `test` (passes CI) → `stable` (in production 30+ days with acceptable FP rate) |
| Selections | `selection_*` for what to match, `filter_*` for exclusions, `susp_*` for alternative indicators combined with `1 of susp_*` |
| Paths | Match with `endswith '\binary.exe'`, never `contains 'binary'` |

## Writing good tests

Each line in a `.jsonl` file is one event. Use field names as they appear in Sysmon / Windows logs, and add a `_case` field describing what the sample represents. It appears in the test report.

```json
{"_case": "renamed binary caught via OriginalFileName", "EventID": 1, "Image": "C:\\Users\\Public\\svc.exe", "OriginalFileName": "PowerShell.EXE", "CommandLine": "svc.exe -EncodedCommand VwBy..."}
```

The most valuable true-negative cases are the ones that **almost** match:

- the same binary doing something legitimate,
- the same command-line flag in a different program,
- the known management agent that uses the same technique.

## Common mistakes

1. **Filtering a whole directory** (`C:\Windows\System32\`) and accidentally excluding the LOLBin you are trying to catch. See the LSASS rule for the right pattern.
2. **Matching literal flags** (`-enc`) when the program accepts abbreviations and alternative prefixes.
3. **Matching the image name only**: attackers rename binaries. Add `OriginalFileName`.
4. **No negative tests**: a rule that matches everything passes every positive test.
