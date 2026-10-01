# Active Directory Threat Detection & Response Lab

A multi-scenario Windows security lab covering detection engineering, alert correlation, and response validation across three common enterprise attack paths.

This repository is a portfolio capstone built from three focused lab scenarios. The scenarios intentionally share Wazuh, Sysmon, Windows telemetry, and Active Response so the detection-to-containment workflow can be compared across different attack surfaces.

## Scenarios

| Scenario | Primary question | Main telemetry | Response focus |
| --- | --- | --- | --- |
| [Kerberos Detection & SOAR Containment](kerberos-detection-soar/README.md) | Can we detect credential-access activity against Active Directory? | Windows Events 4768, 4769, 4662 | LDAP identity containment, Telegram briefing, anti-DoS policy |
| [Lateral Movement & Host Isolation](lateral-movement-containment/README.md) | Can we detect and block WMI/WinRM remote execution? | Sysmon Event 1, Security Event 4624 | Source-IP correlation, Windows Defender Firewall isolation |
| [Ransomware Canary & Memory Triage](ransomware-memory-triage/README.md) | Can we stop a file-encryption process while preserving volatile evidence? | Sysmon Event 11, Wazuh alert JSON | Process suspension, ProcDump memory capture, termination |

## Architecture

```text
Windows / Active Directory telemetry
        |
        v
Sysmon + Windows Security Events
        |
        v
Wazuh Manager and custom detection rules
        |
        v
Active Response / SOAR worker
        |
        +--> Identity containment / Telegram briefing
        +--> Firewall isolation / process audit
        +--> Memory and network artifact capture
        |
        v
Screenshots, logs, and verification evidence
```

## What This Portfolio Demonstrates

- Detection rules tied to concrete Windows event fields instead of tool-name-only claims.
- Correlation across telemetry sources when a single event is missing context.
- Response safeguards against false containment and self-inflicted denial of service.
- Verification evidence showing whether containment actually worked.
- Explicit lab limitations and production considerations.

## Scope

This is an isolated VMware proof-of-concept lab. It is intended for learning and portfolio demonstration, not direct production deployment. Credentials, IP addresses, Active Response scope, alert thresholds, and artifact storage require hardening before enterprise use.

## Repository Layout

```text
ad-threat-detection-and-response-lab/
├── kerberos-detection-soar/
├── lateral-movement-containment/
├── ransomware-memory-triage/
├── .gitignore
└── README.md
```

## Author

Le Hoang - Cybersecurity student focused on SOC analysis, detection engineering, and Windows incident response.

GitHub: https://github.com/LeeHoang26
