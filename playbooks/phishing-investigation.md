# Phishing Investigation — Response Playbook

## Overview

- Incident type: Email-based credential theft, malicious attachment, malicious URL, business email compromise attempt, or user-reported suspicious email.
- Severity level: Medium; High if credentials were entered, malware executed, multiple users received the message, or ePHI exposure is possible.
- Affected systems: HealPath mailboxes, Windows clients, browsers, DNS resolvers `192.168.1.19` and `192.168.1.23`, Wazuh-monitored endpoints, AD accounts.
- Relevant MITRE ATT&CK technique: [T1566 - Phishing](https://attack.mitre.org/techniques/T1566/).

## Detection

- Detected by user report, email security gateway, Wazuh endpoint activity, Splunk correlation, AdGuard DNS logs, Snort IDS, or suspicious authentication after email delivery.
- Wazuh indicators:
  - Rule `554`: File added to the system after attachment download.
  - Rule `550`: Integrity checksum changed after malicious file modification.
  - Rule `60122`: Failed logon if credentials are tested.
  - Rule `60106`: Successful logon if credentials are used.
- Relevant logs:
  - Mail trace/message tracking logs.
  - Email headers from the reported message.
  - Browser download history where available.
  - DNS queries to AdGuard `192.168.1.19` and `192.168.1.23`.
  - Windows Event ID `4688` for opened attachments or spawned scripts.
  - Wazuh FIM alerts for downloaded files.
- Splunk SPL examples:

```spl
index=wazuh (rule.id=554 OR win.system.eventID=4688)
| search ("invoice" OR "payment" OR "password" OR "verify" OR "docsign" OR "onedrive")
| table _time agent.name user rule.id rule.description syscheck.path win.eventdata.commandLine
| sort - _time
```

```spl
index=dns (query="*.ru" OR query="*.top" OR query="*.zip" OR query="*.mov")
| stats count values(src_ip) as clients by query
| sort - count
```

- Example sanitized phishing header indicators:

```text
From: "HealPath Billing" <billing@healpath-example.com>
Reply-To: support@secure-portal-example.net
Return-Path: bounce@mailer.example.net
Received-SPF: fail
Authentication-Results: dkim=fail; dmarc=fail; spf=fail
Subject: Urgent: Patient Invoice Review Required
URL observed: hxxps://secure-portal-example.net/login
```

## Triage

- Ask who reported the email, when it was received, and whether they clicked a link, opened an attachment, replied, or entered credentials.
- Identify all recipients and whether the email is still present in mailboxes.
- Review sender, reply-to, return-path, SPF, DKIM, DMARC, URLs, attachments, and display-name spoofing.
- Defang and record IOCs:
  - Sender address.
  - Sending IP.
  - Subject.
  - URLs and domains.
  - Attachment names and hashes.
- Determine if the lure references patients, invoices, HR, payroll, clinical documents, Microsoft 365, or VPN.
- Treat as true positive if authentication fails, URL mismatch, domain age, malicious attachment, credential form, or known phishing infrastructure is confirmed.

## Containment

- Remove the email from all mailboxes using the approved mail platform tools.
- Block sender domain, sending IP, URL, and attachment hash in the email gateway where available.
- Block malicious domains in AdGuard DNS:

```text
AdGuard Home > Filters > DNS blocklists > Custom filtering rules
||secure-portal-example.net^
||mailer-example-phish.com^
```

- Block malicious destination IPs in PfSense:

```sh
pfctl -t blocked_phishing -T add 203.0.113.88
```

- If credentials were entered, disable account and reset password:

```powershell
Disable-ADAccount -Identity jane.smith
Set-ADAccountPassword -Identity jane.smith -Reset -NewPassword (Read-Host -AsSecureString "New temporary password")
```

- If attachment executed, isolate the workstation and follow the malware playbook.

## Investigation

- Analyze headers:
  - Confirm sending path using `Received` headers from bottom to top.
  - Validate SPF, DKIM, and DMARC results.
  - Compare `From`, `Reply-To`, `Return-Path`, and display name.
  - Identify sending IP and mail provider.
- Extract URLs safely without opening them in a normal browser.
- Check DNS query logs for clicks:

```spl
index=dns query="secure-portal-example.net"
| stats count min(_time) as firstSeen max(_time) as lastSeen by src_ip, user
| convert ctime(firstSeen) ctime(lastSeen)
```

- Check endpoint process activity for attachment execution:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=(Get-Date).AddHours(-24)} |
  Where-Object {$_.Message -match "Downloads|AppData|Temp|powershell|wscript|mshta|rundll32"} |
  Select-Object TimeCreated, Id, Message
```

- Check authentication after reported click:

```spl
index=wazuh (win.system.eventID=4624 OR win.system.eventID=4625)
win.eventdata.targetUserName="jane.smith"
| table _time agent.name win.system.eventID win.eventdata.ipAddress win.eventdata.logonType
| sort _time
```

- Linux and network checks:

```sh
dig secure-portal-example.net
whois secure-portal-example.net
curl -I --max-time 10 hxxp://example.invalid
```

- Timeline reconstruction:
  - Email delivery.
  - User open/click/download/reply.
  - DNS lookup.
  - Attachment execution or credential submission.
  - Suspicious authentication.
  - Containment and notification.

## Eradication

- Remove malicious emails from all mailboxes.
- Delete downloaded attachments from affected endpoints after evidence collection.
- Reset credentials and revoke sessions for users who clicked or entered credentials.
- Remove mailbox forwarding rules created after compromise:

```powershell
Get-InboxRule -Mailbox jane.smith | Select-Object Name,ForwardTo,RedirectTo,Enabled
```

- Remove suspicious browser extensions or unauthorized applications if found.
- Update email gateway, DNS, Wazuh, and Splunk detections with IOCs.

## Recovery

- Re-enable user access after password reset, MFA verification, and endpoint checks.
- Confirm no further authentication attempts from phishing infrastructure.
- Confirm malicious email is no longer present in HealPath mailboxes.
- Validate that blocked domains resolve to sinkhole/block pages through AdGuard.
- Notify affected users with a short internal advisory if multiple recipients were targeted.

## Lessons Learned

- Document sender, recipients, subject, IOCs, user actions, clicked links, entered credentials, and affected systems.
- Determine if ePHI was disclosed in replies, forms, attachments, or compromised mailbox content.
- Update phishing simulations and user awareness using the real tactic without exposing patient data.
- Tune controls for impersonation, external sender banners, attachment sandboxing, and URL rewriting.

## References

- MITRE ATT&CK: [T1566 - Phishing](https://attack.mitre.org/techniques/T1566/)
- Microsoft: [Anti-phishing protection](https://learn.microsoft.com/microsoft-365/security/office-365-security/anti-phishing-protection-about)
- CISA: [Avoiding Social Engineering and Phishing Attacks](https://www.cisa.gov/news-events/news/avoiding-social-engineering-and-phishing-attacks)
- Wazuh FIM documentation: <https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html>

