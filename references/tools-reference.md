# Tools Reference

## Wazuh

- Deployment: Docker Compose on Ubuntu 24.04.
- Coverage: Approximately 30 HealPath agents.
- Main uses:
  - Windows Event Log collection.
  - Linux authentication log monitoring.
  - File Integrity Monitoring.
  - Rule-based alerting.
  - Endpoint inventory and vulnerability visibility where enabled.
- Useful rule IDs:
  - `60105`: Windows Logon Failure.
  - `60106`: Windows Logon Success.
  - `60115`: User account locked out.
  - `60118`: Windows Workstation Logon Success.
  - `60119`: First time this user logged in this system.
  - `60122`: Unknown user or bad password.
  - `550`: Integrity checksum changed.
  - `553`: File deleted.
  - `554`: File added to the system.
  - `5710`: SSH login using a non-existent user.
  - `5716`: SSHD authentication failed.
  - `5720`: Multiple SSH authentication failures.
- Useful paths:
  - Manager rules: `/var/ossec/ruleset/rules/`
  - Local rules: `/var/ossec/etc/rules/local_rules.xml`
  - Wazuh logs: `/var/ossec/logs/`
  - FIM database on Linux agent: `/var/ossec/queue/fim/db`
  - FIM database on Windows agent: `C:\Program Files (x86)\ossec-agent\queue\fim\db`

## Splunk

- Main uses:
  - Correlate Wazuh alerts, Windows Event IDs, firewall logs, DNS logs, and IDS alerts.
  - Reconstruct incident timelines.
  - Create dashboards for authentication, malware, lockouts, and outbound traffic.
- Useful SPL patterns:

```spl
index=wazuh rule.id=60122
| stats count by win.eventdata.targetUserName, win.eventdata.ipAddress
| sort - count
```

```spl
index=wazuh (rule.id=550 OR rule.id=553 OR rule.id=554)
| stats count by agent.name, syscheck.path
| sort - count
```

```spl
index=firewall action=pass direction=out
| stats sum(bytes_out) as bytes by src_ip, dest_ip, dest_port
| sort - bytes
```

## PfSense

- Main uses:
  - Firewall containment.
  - Source/destination IP blocking.
  - Egress analysis.
  - NAT/VPN visibility.
- Useful actions:
  - Add malicious IPs to aliases.
  - Add WAN/LAN block rules.
  - Review `Status > System Logs > Firewall`.
  - Review Snort alerts if IDS/IPS is enabled.
- Useful CLI examples:

```sh
pfctl -t blocked_bruteforce -T add 203.0.113.45
pfctl -t blocked_bruteforce -T show
pfctl -sr
```

## Snort

- Main uses:
  - IDS/IPS alerting for scans, C2, exploit attempts, suspicious TLS, and brute-force patterns.
  - Additional validation for PfSense traffic findings.
- Analyst notes:
  - Always correlate Snort alerts with firewall flow logs.
  - Preserve signature ID, source, destination, ports, timestamp, and payload metadata.

## Active Directory

- Domain: `healpath.local`
- Domain controller: `192.168.1.14`
- Example accounts: `john.doe`, `jane.smith`, `it.admin`
- Common commands:

```powershell
Get-ADUser john.doe -Properties LockedOut,BadPwdCount,LastBadPasswordAttempt,LastLogonDate
Unlock-ADAccount -Identity john.doe
Disable-ADAccount -Identity john.doe
Get-ADGroupMember "Domain Admins"
```

## AdGuard DNS

- Resolvers:
  - `192.168.1.19`
  - `192.168.1.23`
- Main uses:
  - Review DNS queries during phishing, malware, and exfiltration investigations.
  - Add emergency domain blocks for malicious infrastructure.
- Example custom filter:

```text
||malicious-example.net^
```

## Wireshark

- Main uses:
  - Packet validation for suspicious protocols.
  - Confirming data transfer direction, destination, and volume.
  - Reviewing DNS, HTTP, TLS SNI, SMB, and unusual ports.
- Safe capture guidance:
  - Capture only what is needed.
  - Avoid unnecessary patient data exposure.
  - Store captures with restricted access.

