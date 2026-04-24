# Data Exfiltration — Response Playbook

## Overview

- Incident type: Unusual outbound traffic, large data transfer, suspicious cloud upload, unauthorized file transfer, or potential ePHI exfiltration.
- Severity level: High; Critical if ePHI, billing data, patient records, backups, or credential stores may have left HealPath systems.
- Affected systems: File servers, EHR-related systems, workstations, PfSense firewall, Snort IDS/IPS, DNS resolvers `192.168.1.19` and `192.168.1.23`, Wazuh agents.
- Relevant MITRE ATT&CK technique: [T1041 - Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/).

## Detection

- Detected by PfSense firewall logs, Snort IDS/IPS, Wazuh endpoint logs, Splunk traffic correlation, DNS logs, or user reports.
- Indicators:
  - Large outbound transfers to unknown IPs.
  - Repeated uploads to cloud storage not approved for HealPath.
  - Unusual outbound traffic after hours.
  - DNS queries to newly registered or suspicious domains.
  - Use of `rclone`, `curl`, `scp`, `sftp`, `ftp`, `powershell Invoke-WebRequest`, or browser uploads.
- Wazuh rules commonly involved:
  - Rule `550` or `554` if staging files are created or modified.
  - Rule `60106` if suspicious successful logon preceded the transfer.
  - Rule `60122` if credential testing occurred before exfiltration.
- Relevant log sources:
  - PfSense filter logs.
  - Snort alerts.
  - AdGuard DNS query logs.
  - Windows Security Event ID `4688`.
  - Linux shell history, auth logs, and process/network commands.
  - File server access logs where enabled.
- Splunk SPL examples:

```spl
index=firewall action=pass direction=out
| stats sum(bytes_out) as total_bytes count by src_ip, dest_ip, dest_port
| where total_bytes > 500000000
| eval total_mb=round(total_bytes/1024/1024,2)
| sort - total_mb
```

```spl
index=wazuh win.system.eventID=4688
| search win.eventdata.commandLine="*rclone*" OR win.eventdata.commandLine="*Invoke-WebRequest*" OR win.eventdata.commandLine="*curl*" OR win.eventdata.commandLine="*scp*"
| table _time agent.name win.eventdata.subjectUserName win.eventdata.newProcessName win.eventdata.commandLine
```

- Example sanitized PfSense log:

```text
2026-04-25T02:14:33 pfSense filterlog: pass out LAN 192.168.1.42:51622 -> 198.51.100.25:443 TCP bytes_out=2147483648 rule="Default allow LAN to any"
```

## Triage

- Identify source host, user, destination IP/domain, protocol, port, byte count, and time range.
- Determine whether the destination is approved business software, backup, cloud storage, vendor support, or unknown.
- Check whether the source host stores or accesses ePHI.
- Ask the user or system owner whether the transfer was expected.
- Compare transfer volume to normal baseline for the workstation or server.
- Treat as true positive if transfer is large, unusual, after hours, to unknown hosting, preceded by suspicious login, or uses unauthorized tools.

## Containment

- Block destination IP/domain on PfSense:

```sh
pfctl -t blocked_exfil_destinations -T add 198.51.100.25
```

- Add DNS block in AdGuard:

```text
||suspicious-upload-example.net^
```

- Isolate the source endpoint:

```powershell
Disable-NetAdapter -Name "Ethernet" -Confirm:$false
Disable-NetAdapter -Name "Wi-Fi" -Confirm:$false
```

- Disable the user account if suspicious activity is user-driven:

```powershell
Disable-ADAccount -Identity john.doe
```

- Preserve firewall logs, DNS logs, endpoint logs, and file access evidence.
- Notify Security Officer/Privacy Officer if ePHI may be involved.

## Investigation

- PfSense review:
  - Filter by source IP, destination IP, destination port, action, and time.
  - Export logs for the incident window.
  - Check NAT and VPN mappings to identify the internal host.
- Snort review:
  - Search for alerts tied to source IP and destination.
  - Review signatures for C2, file upload, suspicious TLS, or malware family.
- Windows endpoint checks:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=(Get-Date).AddHours(-12)} |
  Where-Object {$_.Message -match "curl|rclone|scp|ftp|powershell|Invoke-WebRequest|bitsadmin"} |
  Select-Object TimeCreated, Id, Message
```

```powershell
Get-ChildItem -Path C:\Users\john.doe -Recurse -ErrorAction SilentlyContinue |
  Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-2)} |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 50 FullName,Length,LastWriteTime
```

- Linux endpoint checks:

```sh
sudo ss -tunap
sudo lsof -i -P -n
sudo find /home /tmp /var/tmp -type f -mtime -2 -size +50M -ls 2>/dev/null
sudo grep -R "rclone\|scp\|sftp\|curl\|wget" /home/*/.bash_history 2>/dev/null
```

- DNS investigation:

```spl
index=dns src_ip="192.168.1.42"
| stats count values(query) as queries by _time
| sort _time
```

- Timeline reconstruction:
  - Account logon.
  - File staging.
  - DNS lookup.
  - First outbound connection.
  - Peak transfer volume.
  - Block and isolation time.

## Eradication

- Remove unauthorized transfer tools and scripts.
- Remove malicious persistence if malware initiated the transfer.
- Rotate credentials used on the source host.
- Review and revoke unauthorized cloud tokens, API keys, browser sessions, or saved credentials.
- Remove unauthorized local admin rights.
- Validate that no scheduled task, service, cron job, or script continues transfer attempts.

## Recovery

- Restore network access only after endpoint review is complete.
- Confirm firewall and DNS blocks remain for malicious destinations.
- Validate business applications still connect to approved destinations.
- Monitor the source user and endpoint for repeat outbound spikes.
- Complete HIPAA risk assessment if ePHI may have been involved.

## Lessons Learned

- Document data types, estimated volume, affected patients if known, systems involved, and whether data was encrypted.
- Update DLP procedures, firewall egress rules, DNS filtering, and cloud upload controls.
- Add Splunk alerts for outbound volume baselines per endpoint.
- Review least privilege for file shares containing ePHI.
- Confirm backups and audit logs are retained long enough for healthcare investigations.

## References

- MITRE ATT&CK: [T1041 - Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)
- PfSense documentation: <https://docs.netgate.com/pfsense/en/latest/>
- Snort documentation: <https://docs.snort.org/>
- HHS HIPAA Breach Notification Rule: <https://www.hhs.gov/hipaa/for-professionals/breach-notification/index.html>

