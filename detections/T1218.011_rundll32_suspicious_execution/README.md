# Rundll32 Proxy Execution From Suspicious Context

| | |
|---|---|
| **ATT&CK** | [T1218.011](https://attack.mitre.org/techniques/T1218/011/) |
| **Tactics** | defense-evasion |
| **Severity** | `high` |
| **Rule** | [`rule.yml`](rule.yml) · id `7bc31caf-8287-4c8e-9936-381e4ab88410` |
| **Tests** | 4 true-positive · 3 true-negative |

## Telemetry required
Sysmon **EID 1** or Security **4688** with command line.

## How the detection works
`rundll32.exe` is signed by Microsoft and therefore often trusted by application control. The rule combines the image (path **or** `OriginalFileName`, so renaming does not help) with **any one of four abuse patterns** (`1 of susp_*`):

| Selection | Abuse |
|---|---|
| `susp_script` | `javascript:` / `RunHTMLApplication` proxying script execution through mshtml |
| `susp_path` | DLL loaded from a user-writable directory |
| `susp_minidump` | `comsvcs.dll MiniDump` LSASS dumping |
| `susp_noargs` | rundll32 with **no arguments**, a classic sacrificial process for injection (Cobalt Strike's default `spawnto`) |

## Evasion & coverage gaps (purple-team notes)
- DLLs copied into `System32` first (requires admin) - cover with file-creation monitoring.
- Export called by ordinal from a legitimately-located but malicious DLL.
- Network beaconing from rundll32 (Sysmon EID 3) is a powerful complement for the no-args case.

## False positives & tuning
Old installers that unpack DLLs into `%TEMP%`. Validate the parent process and the signer of the loaded DLL (Sysmon EID 7).

## SOC triage playbook
1. Retrieve the referenced DLL and hash it; check signer and prevalence across the fleet.
2. For no-args rundll32: look for network connections and injected threads (Sysmon EID 8) from that PID.
3. Map the parent chain back to the initial access vector.

## Emulation
`Invoke-PurpleEmulation -Technique T1218.011` runs the harmless `javascript:` mshtml variant that immediately closes. Atomic Red Team equivalent: tests under **T1218.011**.

## Validate locally
```bash
python tools/run_tests.py --filter T1218.011
python tools/convert.py --backend kql --rule detections/T1218.011_rundll32_suspicious_execution/rule.yml
```
