# MITRE ATT&CK Mapping

| Incident | Playbook | MITRE Technique | Tactic | Why It Applies |
| --- | --- | --- | --- | --- |
| Brute Force Attack | `playbooks/brute-force-attack.md` | [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/) | Credential Access | Repeated password attempts against AD, SSH, RDP, VPN, or applications. |
| Unauthorized Access | `playbooks/unauthorized-access.md` | [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/) | Defense Evasion, Persistence, Privilege Escalation, Initial Access | Attacker or unauthorized user uses real HealPath credentials to access systems. |
| Malware Detection | `playbooks/malware-detection.md` | [T1059 - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/) | Execution | Malware frequently launches PowerShell, cmd, bash, Python, or script interpreters. |
| Phishing Investigation | `playbooks/phishing-investigation.md` | [T1566 - Phishing](https://attack.mitre.org/techniques/T1566/) | Initial Access | Email lures deliver malicious links, attachments, or credential-harvesting pages. |
| Account Lockout | `playbooks/account-lockout.md` | [T1110.001 - Password Guessing](https://attack.mitre.org/techniques/T1110/001/) | Credential Access | Lockouts can result from repeated password guesses against one or more accounts. |
| Data Exfiltration | `playbooks/data-exfiltration.md` | [T1041 - Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/) | Exfiltration | Data leaves the environment over attacker-controlled or suspicious outbound channels. |
| Ransomware Response | `playbooks/ransomware-response.md` | [T1486 - Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/) | Impact | Files are encrypted to disrupt operations and extort payment. |

## HealPath Detection Notes

- Map Wazuh rule IDs, Windows Event IDs, Splunk saved searches, PfSense rules, and Snort signatures to these techniques during alert tuning.
- Tag incidents involving ePHI systems with HIPAA review status in the incident report.
- For `healpath.local`, prioritize alerts involving `it.admin`, domain controller `192.168.1.14`, file shares, backup servers, and clinical endpoints.

