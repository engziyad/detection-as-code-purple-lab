# Suspicious Process Access to LSASS Memory

| | |
|---|---|
| **ATT&CK** | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) |
| **Tactics** | credential-access |
| **Severity** | `high` |
| **Rule** | [`rule.yml`](rule.yml) · id `2a0b1b0e-af2b-4426-a58b-72866042c48c` |
| **Tests** | 3 true-positive · 4 true-negative |

## Telemetry required
Sysmon **Event ID 10 (ProcessAccess)** with a rule that includes `TargetImage` = `lsass.exe`. Most baseline Sysmon configs exclude EID 10 for volume reasons, so add a targeted include for LSASS only.

## How the detection works
LSASS holds credential material (NTLM hashes, Kerberos tickets, sometimes cleartext). To dump it, a tool must open a handle with `PROCESS_VM_READ` (0x0010) plus query rights. The rule keys on the **access mask** rather than tool names, so renamed or custom tooling is still caught.

The interesting part is the filter design: binaries under `System32` are excluded **except** `rundll32.exe` and `taskmgr.exe`, because `rundll32 comsvcs.dll,MiniDump` is the most popular living-off-the-land dump technique. A naive "exclude System32" filter (seen in many public rules) silently misses it.

## Evasion & coverage gaps (purple-team notes)
- **Handle duplication / PPL bypass:** tools that duplicate an existing LSASS handle from another process (e.g. via `NtDuplicateObject`) never generate EID 10 against LSASS directly.
- **Direct syscalls with a minimal mask** (`0x1000`) followed by a later re-open.
- **Credential Guard / RunAsPPL** is the real control: detection here is a backstop, not the primary defense.
- Complementary signal: file creation of `*.dmp` in unusual paths (Sysmon EID 11).

## False positives & tuning
EDR, AV and backup agents. Tune by **full signed path**, never by filename alone. Use `SourceImage` + signer allow-listing in your SIEM.

## SOC triage playbook
1. Identify `SourceImage`, its parent, the user, and the signer.
2. Look for a dump file written within ±2 minutes (Sysmon EID 11, `*.dmp`).
3. Check for subsequent authentication anomalies from the host (pass-the-hash: 4624 logon type 9 / NTLM from unusual sources).
4. If confirmed: isolate host, reset credentials of every account that logged on to it since last reboot, including service accounts.

## Emulation
`Invoke-PurpleEmulation -Technique T1003.001 -LabConfirmed -IncludeCredentialAccess` performs the comsvcs MiniDump against LSASS in a lab VM (requires admin, writes the dump to `%TEMP%` and deletes it immediately). Atomic Red Team equivalent: tests under **T1003.001** (comsvcs.dll).

## Validate locally
```bash
python tools/run_tests.py --filter T1003.001
python tools/convert.py --backend kql --rule detections/T1003.001_lsass_memory_access/rule.yml
```
