# Suspicious Service Installation (PsExec-style / Command Services)

| | |
|---|---|
| **ATT&CK** | [T1569.002](https://attack.mitre.org/techniques/T1569/002/), [T1021.002](https://attack.mitre.org/techniques/T1021/002/) |
| **Tactics** | execution, lateral-movement |
| **Severity** | `high` |
| **Rule** | [`rule.yml`](rule.yml) · id `c36a647e-caeb-4c7d-894f-8b5a3619a350` |
| **Tests** | 4 true-positive · 3 true-negative |

## Telemetry required
Windows **System log Event ID 7045** (Service Control Manager - new service installed). Enabled by default. Optionally Security **4697** if *Audit Security System Extension* is enabled.

## How the detection works
Most SMB lateral movement (PsExec, Impacket `psexec.py`/`smbexec.py`, CrackMapExec, many C2 `jump` commands) creates a service on the target. The rule matches **tool fingerprints** rather than one tool:

- `smbexec` uses `%COMSPEC% /Q /c ... \\127.0.0.1\C$\__output` and the default service name `BTOBTO`.
- Impacket `psexec` drops `%SystemRoot%\<8 random letters>.exe` - matched with a regex.
- Sysinternals PsExec creates `PSEXESVC`.
- Any service running `cmd /c`, PowerShell, or a binary in a user-writable path.

## Evasion & coverage gaps (purple-team notes)
- Service name and binary randomized + binary placed in `System32` (requires custom tooling).
- Modifying an **existing** service's `ImagePath` (`sc config`) - no 7045; cover with Sysmon EID 13 on `Services\*\ImagePath`.
- WMI / WinRM / DCOM lateral movement - different telemetry entirely.

## False positives & tuning
Administrators using Sysinternals PsExec. Correlate with change management and the source host (Security 4624 logon type 3 just before).

## SOC triage playbook
1. Find the source: Security **4624 logon type 3** on the target seconds before the 7045, and the corresponding 5140/5145 share access to `ADMIN$`/`C$`.
2. Investigate the source host as compromised.
3. Collect the service binary before it is deleted (Impacket removes it on exit).

## Emulation
`Invoke-PurpleEmulation -Technique T1569.002` creates a demand-start service with `cmd.exe /c echo` and deletes it. Atomic Red Team equivalent: tests under **T1569.002**.

## Validate locally
```bash
python tools/run_tests.py --filter T1569.002
python tools/convert.py --backend kql --rule detections/T1569.002_suspicious_service_installation/rule.yml
```
