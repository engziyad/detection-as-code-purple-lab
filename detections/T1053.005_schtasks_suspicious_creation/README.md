# Scheduled Task Created With Suspicious Action

| | |
|---|---|
| **ATT&CK** | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) |
| **Tactics** | persistence, execution, privilege-escalation |
| **Severity** | `medium` |
| **Rule** | [`rule.yml`](rule.yml) · id `2114b226-991c-4830-9b80-8f5421283af3` |
| **Tests** | 3 true-positive · 2 true-negative |

## Telemetry required
Sysmon **EID 1** / Security **4688**. Complement with Security **4698 (scheduled task created)**, which contains the full task XML, and the `Microsoft-Windows-TaskScheduler/Operational` log.

## How the detection works
The rule only fires on `schtasks /create` **and** an action that is suspicious on its own: user-writable paths, script interpreters, download cradles, or remote creation as SYSTEM (`/s <host> /ru SYSTEM`, a lateral-movement pattern). Legitimate vendor tasks pointing to `Program Files` do not match, which keeps the alert volume low enough for a SOC queue.

## Evasion & coverage gaps (purple-team notes)
- Tasks created via the COM API / PowerShell `Register-ScheduledTask` / WMI never spawn `schtasks.exe` - cover with **4698**.
- Tasks created by writing XML directly to `C:\Windows\System32\Tasks` plus registry (`TaskCache`) - "hidden task" tradecraft.
- Benign path in the task, malicious content in the referenced script.

## False positives & tuning
IT automation scheduling PowerShell scripts. Allow-list by task name **and** script path, never by task name alone.

## SOC triage playbook
1. Pull the task definition (`schtasks /query /tn <name> /xml` or 4698) and the referenced binary/script.
2. Identify who created it and from where (remote `/s` = check source host for compromise).
3. Remove the task only after evidence collection.

## Emulation
`Invoke-PurpleEmulation -Technique T1053.005` creates a task that echoes to `%TEMP%`, then deletes it. Atomic Red Team equivalent: tests under **T1053.005**.

## Validate locally
```bash
python tools/run_tests.py --filter T1053.005
python tools/convert.py --backend kql --rule detections/T1053.005_schtasks_suspicious_creation/rule.yml
```
