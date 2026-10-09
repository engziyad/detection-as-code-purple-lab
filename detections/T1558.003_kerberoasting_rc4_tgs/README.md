# Kerberoasting - RC4 Service Ticket Requested for User Account

| | |
|---|---|
| **ATT&CK** | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) |
| **Tactics** | credential-access |
| **Severity** | `medium` |
| **Rule** | [`rule.yml`](rule.yml) · id `2847ae87-e869-4b37-811b-e7f0da4f9b0b` |
| **Tests** | 2 true-positive · 4 true-negative |

## Telemetry required
Security **4769 (A Kerberos service ticket was requested)** on **domain controllers**. Requires *Audit Kerberos Service Ticket Operations* (Success).

## How the detection works
Any authenticated user can request a service ticket for any SPN; the ticket is encrypted with the service account's password hash and can be cracked offline. Attack tools request **RC4 (0x17)** tickets because RC4 is far faster to crack than AES. In a domain where accounts support AES, a successful RC4 TGS for a **user-based** service account is anomalous. Machine accounts (`$`) and `krbtgt` are excluded because their passwords are long and random.

For production, pair this single-event rule with an **aggregation hunt**: one client requesting many distinct SPNs within minutes.

## Evasion & coverage gaps (purple-team notes)
- Attackers requesting **AES** tickets (Rubeus `/aes`) to blend in - the aggregation hunt still catches volume-based roasting.
- Targeted roasting of a single account - low volume; rely on **honeypot SPN accounts** (any ticket request = alert).
- The real fix: gMSA or 25+ character passwords for service accounts, and disabling RC4.

### Aggregation hunt (KQL)

```kql
SecurityEvent
| where EventID == 4769 and TicketEncryptionType == "0x17" and Status == "0x0"
| where ServiceName !endswith "$" and ServiceName != "krbtgt"
| summarize SPNs = dcount(ServiceName), Services = make_set(ServiceName, 50)
    by TargetUserName, IpAddress, bin(TimeGenerated, 10m)
| where SPNs >= 3
```

## False positives & tuning
Legacy systems that only support RC4. Inventory them, set `msDS-SupportedEncryptionTypes`, and filter by `ServiceName` with a documented exception.

## SOC triage playbook
1. Identify the requesting account (`TargetUserName`) and source IP.
2. Count distinct `ServiceName` values requested by that client in the past hour.
3. Assume the targeted service account passwords are compromised: rotate them.

## Emulation
`Invoke-PurpleEmulation -Technique T1558.003 -Spn <SPN>` requests one service ticket via .NET `KerberosRequestorSecurityToken` (no cracking, no ticket export). Atomic Red Team equivalent: tests under **T1558.003**.

## Validate locally
```bash
python tools/run_tests.py --filter T1558.003
python tools/convert.py --backend kql --rule detections/T1558.003_kerberoasting_rc4_tgs/rule.yml
```
