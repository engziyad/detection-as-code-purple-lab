# Windows Event Log Clearing via Command Line

| | |
|---|---|
| **ATT&CK** | [T1070.001](https://attack.mitre.org/techniques/T1070/001/) |
| **Tactics** | defense-evasion |
| **Severity** | `high` |
| **Rule** | [`rule.yml`](rule.yml) · id `c62bd792-3b92-4bad-819c-fa3c123151d2` |
| **Tests** | 3 true-positive · 2 true-negative |

## Telemetry required
Sysmon **EID 1** / Security **4688**. The resulting artifacts are Security **1102** and System **104** - forward both to the SIEM as an independent detection.

## How the detection works
Covers the three common command-line methods (`wevtutil cl`, PowerShell cmdlets / .NET `EventLogSession.ClearLog`, and WMIC `cleareventlog`). Detecting at process creation means you still get an alert when log *forwarding* is fast enough to capture the command but the attacker cleared the local log, and it records **who** ran it.

## Evasion & coverage gaps (purple-team notes)
- Clearing through the Event Viewer GUI or the Win32 API (`ClearEventLogW`) from a custom binary - only 1102/104 will show.
- **Selective** event deletion / log tampering (e.g. Mimikatz `event::drop`, Invoke-Phant0m killing EventLog threads) - detect via **gaps in log volume** (heartbeat monitoring) instead.

## False positives & tuning
VDI / golden-image sealing scripts. These run in maintenance windows on known build hosts - filter by host group.

## SOC triage playbook
1. Treat as high priority: log clearing is almost always post-compromise.
2. Recover what you can from the SIEM (forwarded copies) for the period before the clear.
3. Scope the user account used across other hosts.

## Emulation
`Invoke-PurpleEmulation -Technique T1070.001` creates a dedicated test event log, clears it with `wevtutil cl`, then removes it. Security/System logs are never touched. Atomic Red Team equivalent: tests under **T1070.001** (lab VM only).

## Validate locally
```bash
python tools/run_tests.py --filter T1070.001
python tools/convert.py --backend kql --rule detections/T1070.001_event_log_clearing/rule.yml
```
