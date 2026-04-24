# Brute Force Attack — Response Playbook

## Overview

- Incident type: Repeated failed authentication attempts against Windows, Linux, VPN, RDP, SSH, or exposed internal services.
- Severity level: High; Critical if attempts target privileged accounts, domain controller `192.168.1.14`, remote access portals, or patient-care systems.
- Affected systems: Active Directory domain `healpath.local`, DC `192.168.1.14`, Windows clients such as `WS-001`, Linux servers, VPN, PfSense, Wazuh agents.
- Relevant MITRE ATT&CK technique: [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/).

## Detection

- Detected by Wazuh when failed logons spike for one account, many accounts, one source IP, or one endpoint.
- Wazuh default Windows rules commonly involved:
  - Rule `60105`: Windows Logon Failure.
  - Rule `60122`: Logon Failure - Unknown user or bad password for Event ID `4625`.
  - Rule `60115`: User account locked out for Event ID `4740`.
- Wazuh Linux SSH rules commonly involved:
  - Rule `5710`: Attempt to login using a non-existent SSH user.
  - Rule `5716`: SSHD authentication failed.
  - Rule `5720`: Multiple SSH authentication failures.
- Windows Event IDs:
  - `4625`: An account failed to log on.
  - `4740`: A user account was locked out.
- Linux log sources:
  - `/var/log/auth.log` on Ubuntu/Debian.
  - `/var/log/secure` on RHEL-compatible systems.
  - `journalctl -u ssh -u sshd`.
- PfSense/Snort indicators:
  - Repeated connection attempts to RDP `3389`, SMB `445`, SSH `22`, VPN, or web login pages.
  - Snort alerts for SSH brute force, RDP scanning, or repeated authentication attempts.
- Splunk SPL detection examples:

```spl
index=wazuh (rule.id=60122 OR win.system.eventID=4625)
| stats count min(_time) as firstSeen max(_time) as lastSeen values(agent.name) as hosts by win.eventdata.targetUserName, win.eventdata.ipAddress
| where count >= 10
| convert ctime(firstSeen) ctime(lastSeen)
| sort - count
```

```spl
index=wazuh sourcetype=* (rule.id=5716 OR rule.id=5720 OR "Failed password")
| stats count values(agent.name) as hosts by srcip, user
| where count >= 8
| sort - count
```

- Example sanitized Windows log snippet:

```json
{
  "agent": { "name": "WS-001" },
  "rule": { "id": "60122", "description": "Logon Failure - Unknown user or bad password" },
  "win": {
    "system": { "eventID": "4625", "computer": "WS-001.healpath.local" },
    "eventdata": {
      "targetUserName": "john.doe",
      "ipAddress": "203.0.113.45",
      "logonType": "3",
      "status": "0xc000006d",
      "subStatus": "0xc000006a"
    }
  }
}
```

## Triage

- Identify the target account, source IP, destination host, logon type, and time window.
- Ask whether the user recently changed their password, returned from leave, configured a phone email profile, mapped a drive, or used VPN.
- Check if failures are for one account from many IPs, many accounts from one IP, or many accounts from many IPs.
- Confirm whether the source IP is internal, VPN-assigned, vendor-owned, ISP-owned, or clearly external.
- For Windows `4625`, review:
  - `LogonType 2`: Interactive workstation logon.
  - `LogonType 3`: Network logon such as SMB, mapped drive, service, or scanner.
  - `LogonType 10`: RemoteInteractive/RDP.
- Treat as true positive if failures are high volume, use valid usernames, target privileged accounts, trigger lockouts, come from untrusted IPs, or continue after the user stops activity.
- Treat as likely false positive only after validating stale saved credentials, mobile mail clients, scheduled tasks, service accounts, or misconfigured scanners.

## Containment

- If the source is external, block it at PfSense:

```text
Firewall > Aliases > IP > Add 203.0.113.45 to BLOCKED_BRUTE_FORCE
Firewall > Rules > WAN > Add block rule for source BLOCKED_BRUTE_FORCE
Apply Changes
```

- If CLI access is available on PfSense, add the IP to a table used by a block rule:

```sh
pfctl -t blocked_bruteforce -T add 203.0.113.45
pfctl -t blocked_bruteforce -T show
```

- Disable or reset the targeted AD account if compromise is suspected:

```powershell
Disable-ADAccount -Identity john.doe
Set-ADAccountPassword -Identity john.doe -Reset -NewPassword (Read-Host -AsSecureString "Temporary password")
Unlock-ADAccount -Identity john.doe
```

- Force sign-out and revoke active sessions where supported by the application or VPN platform.
- If an internal host is the source, isolate it from the network before resetting multiple accounts.
- Preserve Wazuh, Windows Security, PfSense, and VPN logs before clearing lockouts or changing passwords.

## Investigation

- Query DC `192.168.1.14` for lockout and failure evidence:

```powershell
Get-WinEvent -ComputerName 192.168.1.14 -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddHours(-6)} |
  Select-Object TimeCreated, ProviderName, Id, Message
```

```powershell
Get-WinEvent -ComputerName 192.168.1.14 -FilterHashtable @{LogName='Security'; Id=4740; StartTime=(Get-Date).AddHours(-6)} |
  Select-Object TimeCreated, Id, Message
```

- Review AD account state:

```powershell
Get-ADUser john.doe -Properties LockedOut,LastBadPasswordAttempt,BadPwdCount,LastLogonDate,PasswordLastSet |
  Select-Object SamAccountName,LockedOut,BadPwdCount,LastBadPasswordAttempt,LastLogonDate,PasswordLastSet
```

- Check Linux SSH failures:

```sh
sudo grep -Ei "failed password|invalid user|authentication failure" /var/log/auth.log | tail -100
sudo journalctl -u ssh -u sshd --since "6 hours ago" | grep -Ei "failed|invalid|failure"
sudo lastb | head -30
```

- Review live network activity on a suspected Linux host:

```sh
sudo ss -tnp
sudo who
sudo last -ai | head -30
```

- Reconstruct the timeline:
  - First failed attempt.
  - Account lockout time.
  - Any successful logon after repeated failures.
  - Firewall block time.
  - Account reset and unlock time.
- Check for successful logon after failures:

```spl
index=wazuh (win.system.eventID=4625 OR win.system.eventID=4624)
(win.eventdata.targetUserName="john.doe" OR win.eventdata.targetUserName="it.admin")
| table _time agent.name win.system.eventID win.eventdata.targetUserName win.eventdata.ipAddress win.eventdata.logonType
| sort _time
```

## Eradication

- Remove saved stale credentials from affected workstations:

```cmd
cmdkey /list
cmdkey /delete:TERMSRV/server-name
```

- Remove unknown scheduled tasks or services using old credentials:

```powershell
Get-ScheduledTask | Where-Object {$_.Principal.UserId -like "*john.doe*"}
Get-CimInstance Win32_Service | Where-Object {$_.StartName -like "*john.doe*"} |
  Select-Object Name, StartName, State
```

- For confirmed attack traffic, keep the firewall block, add monitoring for the source ASN/range, and review exposed services.
- Rotate passwords for targeted privileged accounts and any account with successful suspicious logon.
- Validate that service accounts are not configured for interactive logon.

## Recovery

- Unlock only after the root cause is known:

```powershell
Unlock-ADAccount -Identity john.doe
```

- Confirm no new failures for at least 30 minutes after containment.
- Confirm user can log on normally from an approved HealPath workstation such as `WS-001`.
- Confirm no successful unauthorized `4624` events occurred during the brute force window.
- Remove temporary blocks only if the source is confirmed legitimate and remediated.

## Lessons Learned

- Document source IPs, target accounts, affected systems, lockout times, and whether ePHI systems were reachable.
- Tune Wazuh and Splunk thresholds for repeated `4625`, `4740`, and SSH failures.
- Add high-priority alerts for `it.admin`, domain admin accounts, service accounts, and DC `192.168.1.14`.
- Review external exposure for RDP, VPN, SSH, and web portals.
- Update password policy, account lockout policy, MFA requirements, and user education as needed.

## References

- MITRE ATT&CK: [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)
- Microsoft: [Event 4625 - An account failed to log on](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625)
- Microsoft: [Event 4740 - A user account was locked out](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4740)
- Wazuh default rules: `/var/ossec/ruleset/rules/0580-win-security_rules.xml`
- Wazuh SSH rules: `/var/ossec/ruleset/rules/0095-sshd_rules.xml`
- Splunk Search Reference: <https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/WhatsInThisManual>

