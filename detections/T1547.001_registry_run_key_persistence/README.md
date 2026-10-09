# Run Key Persistence Pointing to Suspicious Location

| | |
|---|---|
| **ATT&CK** | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) |
| **Tactics** | persistence |
| **Severity** | `medium` |
| **Rule** | [`rule.yml`](rule.yml) · id `cd7aa717-e694-4271-889f-019a448ef63b` |
| **Tests** | 3 true-positive · 3 true-negative |

## Telemetry required
Sysmon **EID 13 (RegistryEvent - Value Set)** with includes for `CurrentVersion\Run` and `RunOnce` (present in most community Sysmon configs).

## How the detection works
Writing a Run key value is extremely common for legitimate software, so alerting on the key alone is noise. The rule requires the **data** to point to a user-writable path or a script interpreter, then filters well-known per-user apps (OneDrive, Teams). The negative test with a suspicious path under a *non-Run* key proves the key selection is doing its job.

## Evasion & coverage gaps (purple-team notes)
- Other autostart locations: `Winlogon\Userinit`, `Shell`, `Image File Execution Options`, Startup folder, `UserInitMprLogonScript`. Each deserves its own rule.
- Payload in a trusted path (DLL side-loading next to a legitimate EXE).
- Registry writes via direct `NtSetValueKey` are still seen by Sysmon, but values written offline (hive edit) are not.

## False positives & tuning
Per-user installers (Slack, Zoom, Discord, Spotify) living in `AppData`. Add filters with the full path pattern.

## SOC triage playbook
1. Check the writing process (`Image`) - `reg.exe`, PowerShell or an unsigned binary are suspicious.
2. Hash and analyze the referenced binary.
3. Check whether it already executed (process creation at next logon).

## Emulation
`Invoke-PurpleEmulation -Technique T1547.001` writes a HKCU Run value pointing to a non-existent file in `%TEMP%`, then removes it. Atomic Red Team equivalent: tests under **T1547.001**.

## Validate locally
```bash
python tools/run_tests.py --filter T1547.001
python tools/convert.py --backend kql --rule detections/T1547.001_registry_run_key_persistence/rule.yml
```
