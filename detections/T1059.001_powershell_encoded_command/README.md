# PowerShell Execution With Encoded Command

| | |
|---|---|
| **ATT&CK** | [T1059.001](https://attack.mitre.org/techniques/T1059/001/), [T1027](https://attack.mitre.org/techniques/T1027/) |
| **Tactics** | execution, defense-evasion |
| **Severity** | `medium` |
| **Rule** | [`rule.yml`](rule.yml) · id `31cc8b50-1d60-4c11-8fb0-e4a0a57c46ba` |
| **Tests** | 4 true-positive · 4 true-negative |

## Telemetry required
Sysmon **EID 1** or Security **4688 with command-line auditing** enabled (`Include command line in process creation events`). For full visibility also enable **PowerShell Script Block Logging (4104)**, which records the *decoded* script.

## How the detection works
PowerShell accepts **any unambiguous prefix** of a parameter name: `-e`, `-ec`, `-enc`, `-encod`, `-EncodedCommand` all work, and it also accepts `/` and Unicode dashes (`–`, `—`) as parameter prefixes. Rules matching the literal string `-enc` are trivially evaded.

This rule uses one regex: a dash-like prefix, then `e`, `ec` or `en*`, then whitespace and a Base64 blob of 16+ chars. Matching on `OriginalFileName` from the PE header catches a renamed `powershell.exe`. The tests prove that `-ExecutionPolicy` / `-ep` do **not** trigger it.

## Evasion & coverage gaps (purple-team notes)
- Encoded content passed via environment variables or stdin (`powershell -` with piped input).
- Obfuscation inside a *non-encoded* command (`IEX`, string concatenation, tick marks) - cover with 4104 script-block rules.
- PowerShell hosted in another process (System.Management.Automation.dll loaded by a custom binary - Sysmon EID 7).

## False positives & tuning
Configuration management (SCCM `CcmExec.exe`, Intune, RMM tools). Filter by **parent process path**, as shown with `filter_sccm`.

## SOC triage playbook
1. Decode the blob (UTF-16LE Base64) and review the actual script.
2. Check the parent: Office, `wscript`, `mshta`, or browser parents are high severity.
3. Pivot to 4104 for the same host/time for second-stage content.
4. Check for network connections from the PowerShell process (Sysmon EID 3) and DNS queries (EID 22).

## Emulation
`Invoke-PurpleEmulation -Technique T1059.001` runs a harmless encoded `Write-Output`. Atomic Red Team equivalent: tests under **T1059.001** (PowerShell Command Execution, encoded).

## Validate locally
```bash
python tools/run_tests.py --filter T1059.001
python tools/convert.py --backend kql --rule detections/T1059.001_powershell_encoded_command/rule.yml
```
