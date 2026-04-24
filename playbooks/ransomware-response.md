# Ransomware Response — Response Playbook

## Overview

- Incident type: File encryption, ransom note, mass file modifications, destructive malware, or ransomware-like behavior.
- Severity level: Critical.
- Affected systems: Windows clients, servers, file shares, backups, AD `healpath.local`, DC `192.168.1.14`, Wazuh agents, clinical systems, ePHI repositories.
- Relevant MITRE ATT&CK technique: [T1486 - Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/).

## Detection

- Detected by Wazuh FIM mass file changes, user reports, ransom notes, endpoint alerts, Snort suspicious traffic, or unusual SMB/file server activity.
- Wazuh FIM rules commonly involved:
  - Rule `550`: Integrity checksum changed.
  - Rule `553`: File deleted.
  - Rule `554`: File added to the system.
- Detection pattern:
  - Hundreds or thousands of file modifications in a short time.
  - New extensions such as `.locked`, `.encrypted`, `.pay`, or unknown extension.
  - Ransom note files such as `README_RESTORE.txt`.
  - Processes touching many user documents or shared folders.
- Windows Event IDs:
  - `4688`: Suspicious process creation.
  - `4624`: Logon before encryption activity.
  - `4672`: Privileged logon.
  - `1102`: Audit log cleared.
- Splunk SPL examples:

```spl
index=wazuh (rule.id=550 OR rule.id=553 OR rule.id=554)
| bin _time span=5m
| stats count dc(syscheck.path) as unique_files values(syscheck.path) as sample_files by _time, agent.name
| where count > 100 OR unique_files > 100
| sort - count
```

```spl
index=wazuh win.system.eventID=4688
| search win.eventdata.commandLine="*vssadmin delete shadows*" OR win.eventdata.commandLine="*wbadmin delete*" OR win.eventdata.commandLine="*bcdedit*" OR win.eventdata.commandLine="*cipher /w*"
| table _time agent.name win.eventdata.subjectUserName win.eventdata.newProcessName win.eventdata.commandLine
```

- Example sanitized Wazuh alert pattern:

```json
{
  "agent": { "name": "FS-001" },
  "rule": { "id": "550", "description": "Integrity checksum changed." },
  "syscheck": {
    "path": "D:\\Shares\\Clinical\\patient_schedule.xlsx.locked",
    "event": "modified"
  }
}
```

## Triage

- Confirm whether files are actively being encrypted.
- Identify the first affected host, user, shared path, process, and time.
- Ask users to stop using affected shared drives immediately.
- Determine whether clinical operations or ePHI availability is impacted.
- Check if backups are reachable from the infected host. If yes, protect backups immediately.
- Treat as confirmed ransomware if mass file changes, ransom notes, encryption extensions, shadow copy deletion, or known ransomware indicators are present.

## Containment

- Immediately isolate affected endpoints. Pull network cable if remote commands are delayed.

```powershell
Disable-NetAdapter -Name "Ethernet" -Confirm:$false
Disable-NetAdapter -Name "Wi-Fi" -Confirm:$false
```

- Disable compromised user accounts:

```powershell
Disable-ADAccount -Identity john.doe
Disable-ADAccount -Identity it.admin
```

- Disable SMB access to affected shares if encryption is spreading:

```powershell
Set-SmbShare -Name "Clinical" -FolderEnumerationMode AccessBased
Block-SmbShareAccess -Name "Clinical" -AccountName "HEALPATH\Domain Users" -Force
```

- On PfSense, block known C2 and suspicious outbound traffic.
- Disconnect backup storage from the network if not already immutable/offline.
- Stop scheduled jobs that could overwrite clean backups.
- Notify IT leadership, Security Officer, Privacy Officer, and incident response contacts immediately.
- Do not pay ransom or contact threat actors without executive, legal, and law enforcement guidance.

## Investigation

- Identify patient-care impact, affected shares, encrypted file count, and first affected endpoint.
- Review Wazuh mass FIM alerts:

```spl
index=wazuh (rule.id=550 OR rule.id=553 OR rule.id=554)
| stats count min(_time) as firstSeen max(_time) as lastSeen by agent.name, syscheck.path
| convert ctime(firstSeen) ctime(lastSeen)
```

- Search for ransomware preparation commands:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=(Get-Date).AddHours(-24)} |
  Where-Object {$_.Message -match "vssadmin|wbadmin|bcdedit|wevtutil|cipher|powershell|psexec|wmic"} |
  Select-Object TimeCreated, Id, Message
```

- Check for shadow copy deletion:

```cmd
vssadmin list shadows
```

- Review logons around initial encryption:

```powershell
Get-WinEvent -ComputerName 192.168.1.14 -FilterHashtable @{LogName='Security'; Id=4624,4625,4672; StartTime=(Get-Date).AddHours(-24)} |
  Select-Object TimeCreated, Id, Message
```

- Linux checks if affected:

```sh
sudo find / -name "*README*RECOVER*" -o -name "*.locked" 2>/dev/null | head -100
sudo ps auxf
sudo ss -tunap
sudo journalctl --since "24 hours ago" | grep -Ei "delete|encrypt|cron|ssh|sudo"
```

- Timeline reconstruction:
  - Initial access.
  - Privilege escalation.
  - Lateral movement.
  - Backup deletion attempts.
  - Encryption start.
  - Containment actions.
  - Recovery start.

## Eradication

- Preserve forensic evidence before wiping systems.
- Remove ransomware binaries, persistence, scheduled tasks, services, and stolen tools only after evidence capture.
- Reimage compromised endpoints and servers when possible.
- Rotate passwords for affected users, local admins, domain admins, service accounts, and backup accounts.
- Review AD for new users, group changes, GPO changes, and suspicious delegation.
- Remove unauthorized remote access tools.
- Patch exploited systems and close exposed services.

## Recovery

- Validate backups before restoring:
  - Confirm backup date is before encryption.
  - Confirm backup integrity.
  - Confirm backup is not encrypted or tampered with.
  - Restore to a clean isolated environment first.
- Rebuild priority order:
  - Domain services and DNS.
  - Network security services.
  - Clinical systems and ePHI access.
  - File shares.
  - User workstations.
- Restore systems from clean backups or golden images.
- Confirm Wazuh agent health after rebuild:

```sh
sudo /var/ossec/bin/agent_control -l
```

- Validate no new FIM mass-change alerts or ransomware process activity.
- Keep temporary network segmentation until all restored systems are validated.

## Lessons Learned

- Document affected systems, encrypted file paths, patient-care impact, downtime, recovery times, and ePHI exposure assessment.
- HIPAA breach analysis must determine whether ePHI was accessed, acquired, used, disclosed, encrypted, or unavailable in a way that creates reportable obligations.
- Notify HHS without unreasonable delay and no later than 60 calendar days when a breach affects 500 or more individuals; breaches affecting fewer than 500 individuals are reported no later than 60 days after the end of the calendar year.
- Update Wazuh FIM thresholds, ransomware detections, backup isolation, segmentation, MFA, patch management, and privileged access controls.
- Conduct a tabletop review and update this playbook with actual gaps found.

## References

- MITRE ATT&CK: [T1486 - Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- HHS HIPAA Breach Notification Rule: <https://www.hhs.gov/hipaa/for-professionals/breach-notification/index.html>
- CISA Stop Ransomware: <https://www.cisa.gov/stopransomware>
- Microsoft: [Event 4688](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4688)
- Wazuh FIM documentation: <https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html>

