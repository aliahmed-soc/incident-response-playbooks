# Unauthorized Access — Response Playbook

## Overview

- Incident type: Suspicious successful authentication, valid account abuse, impossible travel, unusual login time, unexpected privileged access, or access from an unapproved host.
- Severity level: High; Critical if `it.admin`, Domain Admin, EHR, file shares with ePHI, or DC `192.168.1.14` are involved.
- Affected systems: Active Directory `healpath.local`, Windows clients `WS-001` and later, servers, VPN, clinical workstations, file shares.
- Relevant MITRE ATT&CK technique: [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/).

## Detection

- Detected by Wazuh user activity monitoring, Windows Security logs, Splunk correlation, VPN logs, and AD audit events.
- Windows Event IDs:
  - `4624`: Successful logon.
  - `4648`: A logon was attempted using explicit credentials.
  - `4672`: Special privileges assigned to new logon.
  - `4776`: Credential validation by domain controller.
  - `4768` and `4769`: Kerberos authentication activity.
- Wazuh rules commonly involved:
  - Rule `60106`: Windows Logon Success for `4624`.
  - Rule `60118`: Windows Workstation Logon Success.
  - Rule `60119`: First time this user logged in this system.
  - Rule `60103`: Windows audit success event, useful for events collected but not matched by a more granular rule.
- Relevant log sources:
  - Domain controller Security log on `192.168.1.14`.
  - Endpoint Security logs from `WS-001`, `WS-002`, and servers.
  - VPN authentication logs.
  - Wazuh `archives.json` and alerts.
  - Splunk indexed Windows and Wazuh logs.
- Splunk SPL examples:

```spl
index=wazuh win.system.eventID=4624 win.eventdata.targetUserName IN ("john.doe","jane.smith","it.admin")
| eval hour=strftime(_time,"%H")
| where hour < 6 OR hour > 20
| table _time agent.name win.eventdata.targetUserName win.eventdata.ipAddress win.eventdata.logonType win.eventdata.workstationName
| sort _time
```

```spl
index=wazuh (win.system.eventID=4672 OR win.system.eventID=4648)
| table _time agent.name win.system.eventID win.eventdata.subjectUserName win.eventdata.targetUserName win.eventdata.processName win.eventdata.ipAddress
| sort - _time
```

- Example sanitized log snippet:

```json
{
  "agent": { "name": "WS-014" },
  "rule": { "id": "60119", "description": "First time this user logged in this system" },
  "win": {
    "system": { "eventID": "4624", "computer": "WS-014.healpath.local" },
    "eventdata": {
      "targetUserName": "it.admin",
      "targetDomainName": "HEALPATH",
      "logonType": "10",
      "ipAddress": "198.51.100.77",
      "workstationName": "UNKNOWN"
    }
  }
}
```

## Triage

- Ask whether the user was working at that time and from that location.
- Confirm whether the source IP is internal, VPN, remote access gateway, vendor network, or unknown.
- Identify logon type:
  - `2`: Console.
  - `3`: Network access.
  - `7`: Unlock.
  - `10`: RDP.
  - `11`: Cached interactive.
- Check whether the account used MFA and whether the MFA prompt was approved by the legitimate user.
- Review whether the endpoint is normal for that user. `jane.smith` logging into `WS-002` may be normal; `jane.smith` logging into a server or `WS-014` after hours may not be.
- Check for prior failures from the same IP or account.
- Treat as true positive if there is unusual geography, impossible timing, first-time host access, privileged token assignment, explicit credential use, or activity denied by the user.

## Containment

- Disable the account if misuse is likely:

```powershell
Disable-ADAccount -Identity jane.smith
```

- Reset password and revoke active sessions where supported:

```powershell
Set-ADAccountPassword -Identity jane.smith -Reset -NewPassword (Read-Host -AsSecureString "New temporary password")
Set-ADUser jane.smith -ChangePasswordAtLogon $true
```

- If privileged access occurred, disable or rotate related admin credentials:

```powershell
Disable-ADAccount -Identity it.admin
```

- Block the source IP in PfSense if external:

```sh
pfctl -t blocked_unauthorized_access -T add 198.51.100.77
```

- Isolate the endpoint if the account was used from an internal workstation that may be compromised.
- Preserve Security, Sysmon if available, Wazuh, VPN, and firewall logs before remediation.

## Investigation

- Pull successful and privileged logons from the DC:

```powershell
Get-WinEvent -ComputerName 192.168.1.14 -FilterHashtable @{LogName='Security'; Id=4624,4648,4672; StartTime=(Get-Date).AddHours(-24)} |
  Where-Object {$_.Message -match "jane.smith|it.admin"} |
  Select-Object TimeCreated, Id, ProviderName, Message
```

- Review AD user properties:

```powershell
Get-ADUser jane.smith -Properties LastLogonDate,PasswordLastSet,MemberOf,Enabled,LockedOut |
  Select-Object SamAccountName,Enabled,LockedOut,LastLogonDate,PasswordLastSet,MemberOf
```

- Check group membership changes:

```powershell
Get-WinEvent -ComputerName 192.168.1.14 -FilterHashtable @{LogName='Security'; Id=4728,4732,4756; StartTime=(Get-Date).AddDays(-7)} |
  Where-Object {$_.Message -match "jane.smith|it.admin"} |
  Select-Object TimeCreated, Id, Message
```

- On the endpoint, check recent sessions and processes:

```powershell
quser
Get-Process | Sort-Object StartTime -Descending -ErrorAction SilentlyContinue | Select-Object -First 20 Name,Id,StartTime,Path
Get-EventLog -LogName Security -InstanceId 4624 -After (Get-Date).AddHours(-12)
```

- Linux host checks:

```sh
who
last -ai | head -50
sudo grep -E "Accepted password|Accepted publickey|session opened" /var/log/auth.log | tail -100
sudo journalctl --since "24 hours ago" | grep -Ei "sudo|su|session opened|accepted"
```

- Timeline reconstruction:
  - First suspicious logon.
  - Prior failed attempts.
  - Privilege assignment or group changes.
  - File share, EHR, or ePHI access.
  - Password reset, containment, and user verification.

## Eradication

- Remove unauthorized group membership:

```powershell
Remove-ADGroupMember -Identity "Domain Admins" -Members jane.smith -Confirm:$false
```

- Remove persistence created by the account:

```powershell
Get-ScheduledTask | Where-Object {$_.Principal.UserId -match "jane.smith|it.admin"}
Get-LocalUser
Get-LocalGroupMember Administrators
```

- Reimage or deeply clean endpoints used by the unauthorized account if malware or credential theft is suspected.
- Rotate passwords for affected accounts and any service account touched by the session.
- Review mailbox forwarding rules and OAuth/application grants if email access was involved.

## Recovery

- Re-enable the account only after identity validation and password reset:

```powershell
Enable-ADAccount -Identity jane.smith
Unlock-ADAccount -Identity jane.smith
```

- Confirm successful logon from an approved HealPath workstation.
- Confirm no new `4624`, `4648`, or `4672` events from suspicious IPs.
- Validate access to ePHI systems is appropriate and least-privilege.
- Keep enhanced monitoring on the account for at least 7 days.

## Lessons Learned

- Document all accounts, hosts, IPs, timestamps, and accessed systems.
- Determine whether ePHI was accessed, viewed, changed, copied, or disclosed.
- Update Wazuh/Splunk alerts for off-hours logons, first-time host logons, `4672`, and explicit credential use.
- Review MFA coverage, privileged account separation, and local administrator rights.
- Add watchlists for privileged users and sensitive systems.

## References

- MITRE ATT&CK: [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- Microsoft: [Event 4624](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624)
- Microsoft: [Event 4648](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4648)
- Microsoft: [Event 4672](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4672)
- Wazuh default rules: `/var/ossec/ruleset/rules/0580-win-security_rules.xml`

