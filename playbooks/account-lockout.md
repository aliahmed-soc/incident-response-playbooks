# Account Lockout — Response Playbook

## Overview

- Incident type: Active Directory user account lockout from repeated failed authentication.
- Severity level: Medium; High if many accounts lock out, `it.admin` locks out, or the source is external or unknown.
- Affected systems: Active Directory `healpath.local`, DC `192.168.1.14`, Windows clients, mobile mail clients, mapped drives, VPN, services, scheduled tasks.
- Relevant MITRE ATT&CK technique: [T1110.001 - Password Guessing](https://attack.mitre.org/techniques/T1110/001/).

## Detection

- Detected by Wazuh from Windows Event ID `4740`; this detection is already configured in the HealPath production environment.
- Wazuh default rule:
  - Rule `60115`: User account locked out (multiple login errors), triggered by Event ID `4740`.
- Related Windows Event IDs:
  - `4740`: A user account was locked out.
  - `4625`: Failed logon.
  - `4771`: Kerberos pre-authentication failed.
  - `4776`: Domain controller attempted to validate credentials.
- Relevant log sources:
  - Domain controller Security log on `192.168.1.14`.
  - Endpoint Security logs.
  - Wazuh alerts and archives.
  - VPN and mail authentication logs.
- Splunk SPL examples:

```spl
index=wazuh (rule.id=60115 OR win.system.eventID=4740)
| table _time agent.name win.eventdata.targetUserName win.eventdata.targetDomainName win.eventdata.callerComputerName
| sort - _time
```

```spl
index=wazuh win.system.eventID=4625 win.eventdata.targetUserName="john.doe"
| stats count values(win.eventdata.ipAddress) as source_ips values(agent.name) as hosts by win.eventdata.logonType, win.eventdata.workstationName
| sort - count
```

- Example sanitized Wazuh alert:

```json
{
  "agent": { "name": "DC-01" },
  "rule": { "id": "60115", "level": 9, "description": "User account locked out (multiple login errors)" },
  "win": {
    "system": { "eventID": "4740", "computer": "DC-01.healpath.local" },
    "eventdata": {
      "targetUserName": "john.doe",
      "targetDomainName": "HEALPATH",
      "callerComputerName": "WS-003"
    }
  }
}
```

## Triage

- Confirm the locked account, caller computer, lockout time, and whether the user is actively working.
- Ask the user about password changes, mobile device email, mapped drives, VPN, RDP sessions, saved browser passwords, and old workstation sessions.
- Check if only one user is affected or multiple users are locking out.
- Confirm whether `callerComputerName` is a known HealPath endpoint such as `WS-003`.
- Review whether the same account has successful logons from unexpected sources.
- User error indicators:
  - One user, one known workstation, immediately after password change.
  - Stale credential on phone, Outlook, mapped drive, or scheduled task.
- Attack indicators:
  - Multiple users, one source IP.
  - Lockouts outside business hours.
  - Privileged account lockout.
  - External VPN or firewall source.

## Containment

- Do not unlock repeatedly until the source is known.
- If attack is suspected, disable account:

```powershell
Disable-ADAccount -Identity john.doe
```

- If source is a known workstation with stale credentials, disconnect mapped sessions:

```cmd
net use
net use * /delete
cmdkey /list
```

- If a suspicious source IP is identified, block it at PfSense:

```sh
pfctl -t blocked_lockout_sources -T add 203.0.113.45
```

- If the caller computer is unknown or suspected compromised, isolate it from the network.

## Investigation

- Check AD account details:

```powershell
Get-ADUser john.doe -Properties LockedOut,BadPwdCount,LastBadPasswordAttempt,LastLogonDate,PasswordLastSet |
  Select-Object SamAccountName,LockedOut,BadPwdCount,LastBadPasswordAttempt,LastLogonDate,PasswordLastSet
```

- Search lockout events on the DC:

```powershell
Get-WinEvent -ComputerName 192.168.1.14 -FilterHashtable @{LogName='Security'; Id=4740; StartTime=(Get-Date).AddHours(-24)} |
  Where-Object {$_.Message -match "john.doe"} |
  Select-Object TimeCreated, Id, Message
```

- Search failed logons:

```powershell
Get-WinEvent -ComputerName 192.168.1.14 -FilterHashtable @{LogName='Security'; Id=4625,4771,4776; StartTime=(Get-Date).AddHours(-24)} |
  Where-Object {$_.Message -match "john.doe"} |
  Select-Object TimeCreated, Id, Message
```

- On the caller workstation:

```powershell
Get-ScheduledTask | Where-Object {$_.Principal.UserId -like "*john.doe*"}
Get-CimInstance Win32_Service | Where-Object {$_.StartName -like "*john.doe*"} |
  Select-Object Name,State,StartName
cmdkey /list
```

- Review active sessions:

```cmd
query user
net use
```

- Linux source checks if the caller is Linux:

```sh
sudo grep -Ei "john.doe|authentication failure|failed password" /var/log/auth.log | tail -100
sudo smbstatus 2>/dev/null
```

- Timeline reconstruction:
  - Password change time.
  - First bad password attempt.
  - Lockout time.
  - Source workstation or IP.
  - Unlock/reset time.

## Eradication

- Remove stale credentials from Windows Credential Manager and mapped drives.
- Update saved passwords on mobile email clients, Outlook, VPN clients, scanners, and applications.
- Update or remove scheduled tasks and services using the user account.
- If the source is malicious, rotate the user password, disable suspicious sessions, and scan the source endpoint.
- Replace user-based service credentials with managed service accounts where possible.

## Recovery

- Unlock account after root cause is corrected:

```powershell
Unlock-ADAccount -Identity john.doe
```

- Have the user log in from an approved workstation.
- Monitor for repeat `4740` and `4625` events for at least one hour.
- Confirm the user can access required clinical and business systems.
- Document whether patient-care workflow was interrupted.

## Lessons Learned

- Document account, caller computer, lockout source, root cause, and resolution.
- Add known stale credential patterns to analyst notes.
- Tune Wazuh/Splunk alerts for repeated lockouts and privileged account lockouts.
- Review lockout threshold policy and balance security with clinical operations.
- Educate users to update mobile and saved credentials immediately after password changes.

## References

- MITRE ATT&CK: [T1110.001 - Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
- Microsoft: [Event 4740](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4740)
- Microsoft: [Event 4625](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625)
- Wazuh default rules: `/var/ossec/ruleset/rules/0580-win-security_rules.xml`

