# Incident Response Playbooks — SOC Analyst Reference

![SOC](https://img.shields.io/badge/SOC-Analyst-blue)
![SIEM](https://img.shields.io/badge/SIEM-Monitoring-green)
![HIPAA](https://img.shields.io/badge/HIPAA-Healthcare%20Security-red)
![Wazuh](https://img.shields.io/badge/Wazuh-Detection-orange)
![Splunk](https://img.shields.io/badge/Splunk-Search%20%26%20Investigation-black)

## Overview

This repository contains practical incident response playbooks for SOC analysts working in a healthcare IT environment. The playbooks are based on real operational experience monitoring Windows and Linux endpoints, Active Directory activity, Wazuh SIEM alerts, firewall traffic, and security events that can affect HIPAA-covered systems.

The goal is to provide clear, repeatable response steps for common incidents seen in a small-to-mid sized healthcare network, including authentication attacks, unauthorized access, malware activity, phishing, account lockouts, data exfiltration, and ransomware.

These playbooks are written for environments similar to:

- Wazuh SIEM monitoring endpoint and authentication activity
- HealPath healthcare domain: `healpath.local`
- Domain controller: `192.168.1.14`
- Wazuh deployment: Docker Compose on Ubuntu 24.04 with approximately 30 agents
- Active Directory domain services, including `healpath.local`
- Windows and Linux endpoint logging
- PfSense firewall monitoring and blocking
- Dual AdGuard DNS resolvers: `192.168.1.19` and `192.168.1.23`
- Splunk search and correlation
- Snort network intrusion detection
- HIPAA-driven incident documentation and breach analysis

## Playbooks

| Playbook | Description |
| --- | --- |
| [Brute Force Attack](playbooks/brute-force-attack.md) | Response steps for repeated failed authentication attempts against Windows, Linux, VPN, or exposed services. |
| [Unauthorized Access](playbooks/unauthorized-access.md) | Investigation process for suspicious successful logons, unusual access times, privileged logons, or valid account abuse. |
| [Malware Detection](playbooks/malware-detection.md) | Triage, containment, and cleanup steps for suspicious process execution, file integrity alerts, and endpoint malware indicators. |
| [Phishing Investigation](playbooks/phishing-investigation.md) | Workflow for analyzing reported phishing emails, headers, URLs, attachments, and affected users. |
| [Account Lockout](playbooks/account-lockout.md) | Root cause analysis for Active Directory account lockouts, including user error, stale credentials, and password guessing. |
| [Data Exfiltration](playbooks/data-exfiltration.md) | Detection and response steps for unusual outbound traffic, large transfers, and potential HIPAA data exposure. |
| [Ransomware Response](playbooks/ransomware-response.md) | Critical response procedure for mass file changes, encryption activity, isolation, backup validation, and HIPAA breach assessment. |

## How To Use These Playbooks

Use these playbooks during alert triage, active incident response, tabletop exercises, and post-incident process improvement.

1. Start with the playbook that matches the alert type or user report.
2. Review the `Detection` section to confirm the source of the alert and the relevant log evidence.
3. Use the `Triage` section to determine whether the event is a false positive, policy issue, user mistake, or real incident.
4. Follow the `Containment` steps when there is active risk to accounts, endpoints, protected health information, or business operations.
5. Use the `Investigation` commands and log sources to reconstruct the timeline.
6. Complete `Eradication` and `Recovery` only after the threat path is understood.
7. Document findings, evidence, business impact, and HIPAA considerations in the incident report template.

These playbooks are intended to support analyst decision-making. They do not replace organizational policies, legal review, privacy officer review, or HIPAA breach notification procedures.

## Tools Referenced

- **Wazuh**: Endpoint monitoring, file integrity monitoring, authentication alerting, Windows Event Log collection, Linux log collection, and active response.
- **Splunk**: Search, correlation, dashboards, timeline reconstruction, and alert validation using SPL.
- **Active Directory**: User authentication, account lockout analysis, privileged account review, and domain controller log investigation.
- **Windows Event Viewer**: Security event review for logon activity, failed authentication, process creation, privilege use, and account lockouts.
- **Linux System Logs**: Authentication and SSH activity review using `/var/log/auth.log`, `/var/log/secure`, and `journalctl`.
- **PfSense**: Firewall log review, source blocking, destination blocking, and outbound traffic analysis.
- **Snort**: Network intrusion detection and suspicious traffic alerting.
- **Wireshark**: Packet analysis for suspicious network sessions, protocol review, and data transfer validation.

## HIPAA Context

Healthcare incident response requires more than technical containment. Analysts must also consider whether an incident affected electronic protected health information (ePHI), patient care systems, clinical operations, or regulated audit evidence.

For incidents involving unauthorized access, malware, data exfiltration, ransomware, lost credentials, or suspected disclosure of ePHI, responders should document:

- Systems and user accounts involved
- Whether ePHI was accessed, viewed, modified, encrypted, or exfiltrated
- Timeline of detection, containment, eradication, and recovery
- Logs and evidence preserved for compliance review
- Users, departments, patients, or systems potentially affected
- Whether the Privacy Officer, Security Officer, legal counsel, or leadership were notified
- Whether HIPAA breach notification analysis is required

The HIPAA breach notification rule generally requires covered entities to assess impermissible uses or disclosures of unsecured PHI and determine notification obligations. Final breach determination should be made by the appropriate privacy, compliance, and legal stakeholders.

## Skills Demonstrated

- SOC alert triage and incident response
- Wazuh SIEM monitoring and rule-based detection
- Splunk SPL investigation and correlation
- Active Directory security event analysis
- Windows Event ID investigation
- Linux authentication log analysis
- Malware and ransomware response
- Phishing analysis and IOC handling
- Firewall-based containment using PfSense
- Network traffic review with Snort and Wireshark
- MITRE ATT&CK mapping
- HIPAA-aware security documentation
- Post-incident reporting and lessons learned

## Repository Structure

```text
incident-response-playbooks/
├── README.md
├── playbooks/
│   ├── brute-force-attack.md
│   ├── unauthorized-access.md
│   ├── malware-detection.md
│   ├── phishing-investigation.md
│   ├── account-lockout.md
│   ├── data-exfiltration.md
│   └── ransomware-response.md
├── templates/
│   ├── playbook-template.md
│   └── incident-report-template.md
├── references/
│   ├── mitre-attack-mapping.md
│   ├── tools-reference.md
│   └── hipaa-incident-requirements.md
└── .gitignore
```

## Author

**Ali Ahmed**  
IT Specialist | SOC Analyst Focus | Healthcare Security  

This repository reflects hands-on experience supporting healthcare IT operations, monitoring Wazuh SIEM alerts across approximately 30 endpoints, reviewing Active Directory activity, and responding to security events in a HIPAA-regulated environment.
