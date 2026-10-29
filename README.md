# Active Directory Threat Detection & Response Lab

I built this lab to follow Windows alerts from the event fields through investigation and a limited response. It contains two Active Directory scenarios and one Windows endpoint scenario.

The companion [Wazuh Detection Quality and Regression Lab](https://github.com/LeeHoang26/wazuh-detection-quality-lab) tests the detection logic against positive, negative and edge cases. Its offline metrics are separate from the live examples here.

## Setup

The recorded lab used VMware Workstation and Wazuh 4.8 on an isolated `192.168.50.0/24` network.

| Host | Role | Address |
| --- | --- | --- |
| `DC01` | Windows Server 2022, `hoang.vn`, Security event auditing | `192.168.50.10` |
| `WK01` | Windows 10, Sysmon and Wazuh Agent | `192.168.50.20` |
| `SIEM-SRV` | Ubuntu 22.04, Wazuh Manager | `192.168.50.30` |
| `KALI` | Impacket test client | `192.168.50.40` |

Scenario READMEs contain the configuration links and setup details. When collecting canary and lateral telemetry on the same endpoint, merge the Sysmon settings into one configuration. Applying either standalone configuration can replace the other scenario's filters.

## Detection

| Scenario | Telemetry | Rules |
| --- | --- | --- |
| [Kerberos](kerberos-detection-soar/README.md) | Security Events 4768, 4769, 4662 | `100100`, `100101`, `100102` |
| [Lateral movement](lateral-movement-containment/README.md) | Sysmon Event 1 and Security Event 4624 | `100300` |
| [Canary file and process triage](ransomware-memory-triage/README.md) | Sysmon Events 11 and 1 | `100200` |

A match is a reason to investigate. An RC4 ticket, replication GUID, remote shell or canary write can also occur during legitimate activity.

## Response

The handlers take different actions:

- Kerberos sends a Telegram notice. AS-REP account disablement requires `AD_ALLOW_ACCOUNT_DISABLE=true`, identity exclusions, a checked LDAP write and UAC readback. Kerberoasting never disables the service account; `100102` is detection-only in the integration shown.
- Lateral movement correlates the alert's exact logon ID with a preceding network logon, then blocks one source IP on the reporting endpoint. The reported PID is audited only.
- Canary triage logs a review decision by default. `CANARY_ENABLE_RESPONSE=true` enables process actions after Sysmon and live-process identity checks. ProcDump, socket metadata and executable SHA-256 support later analysis.

Both Windows Active Response snippets use `local`, meaning the agent that generated the alert. Missing or conflicting incident identity stops the response; the handlers do not guess from the newest event.

## Evidence

Each scenario retains its recorded screenshots and observations:

- [Kerberos ticket requests, Wazuh alerts and LDAP result](kerberos-detection-soar/README.md#evidence)
- [WMI execution, source-IP block and subsequent connection failures](lateral-movement-containment/README.md#evidence)
- [Canary alert, process dumps and triage artifacts](ransomware-memory-triage/README.md#evidence)

These images document the scenarios and observations described in each README.

## Testing

From this repository root:

```powershell
python -m unittest discover -s kerberos-detection-soar/tests
powershell -NoProfile -File tests\test_active_response.ps1
```

The tests exercise handler decisions and failure paths with mocks. They do not contact LDAP or Telegram or run real containment. Live verification still needs an isolated Windows/Wazuh environment.

## Limits

This is a lab/POC. The response is narrower than full incident containment: one account, one source-IP block or one selected process. Other accounts, hosts, processes and completed writes need separate investigation.

Single-event rules lack a production baseline, frequency thresholds and an approved response policy. LDAP exclusions do not identify every privileged or business-critical account. Dumps require access control, storage limits and review before sharing.

Process dumps do not prove encryption-key recovery. The companion canary live test used an Explorer TXT copy with Active Response disabled; it validated detection coverage rather than ransomware or process-response safety.

## Author

Le Duc Hoang — Cybersecurity student focused on SOC analysis and Windows investigation.

[GitHub](https://github.com/LeeHoang26)
