# HIPAA Incident Requirements

## Purpose

This reference supports HealPath incident documentation when a security event may involve electronic protected health information (ePHI). It is an analyst guide, not legal advice. Final breach determination should be made by HealPath privacy, compliance, legal, and leadership stakeholders.

## When To Start HIPAA Review

Start HIPAA review when an incident may involve:

- Unauthorized access to systems containing ePHI.
- Compromised user credentials with access to patient records.
- Malware or ransomware on clinical systems, file shares, billing systems, or workstations used for patient data.
- Suspected data exfiltration.
- Phishing that caused disclosure of patient information.
- Lost, altered, encrypted, or unavailable ePHI.
- Vendor or business associate systems connected to HealPath data.

## Required Documentation

Document enough detail to support breach risk assessment:

- Incident title and ID.
- Detection date and time.
- Discovery date and time.
- Containment date and time.
- Systems and accounts involved.
- Types of PHI/ePHI involved.
- Whether data was accessed, acquired, used, disclosed, altered, encrypted, or destroyed.
- Whether data was encrypted at rest or in transit.
- Whether the attacker or unauthorized party is known.
- Whether ePHI was actually viewed or exfiltrated.
- Number of individuals potentially affected.
- Actions taken to reduce risk.
- Evidence preserved.
- Notifications made internally.

## HIPAA Breach Risk Assessment Factors

Assess at least:

- Nature and extent of PHI involved, including identifiers and likelihood of re-identification.
- Unauthorized person who used the PHI or received the disclosure.
- Whether PHI was actually acquired or viewed.
- Extent to which risk to the PHI has been mitigated.

## Notification Timing

- Breaches affecting 500 or more individuals: notify HHS without unreasonable delay and no later than 60 calendar days after discovery.
- Breaches affecting fewer than 500 individuals: notify HHS no later than 60 days after the end of the calendar year in which the breach was discovered.
- Individual notifications may also be required without unreasonable delay and no later than 60 calendar days after discovery.
- Media notification may be required for breaches affecting more than 500 residents of a state or jurisdiction.
- Business associates must notify the covered entity after discovering a breach involving the covered entity's unsecured PHI.

## Analyst Actions During Incident Response

- Preserve Wazuh alerts, Windows logs, Linux logs, firewall logs, DNS logs, email evidence, and file hashes.
- Avoid opening patient files unless needed for the investigation and authorized.
- Restrict access to incident evidence containing PHI.
- Mark incident tickets and evidence repositories as confidential.
- Notify the Security Officer and Privacy Officer when ePHI impact is possible.
- Record exact times for detection, containment, eradication, recovery, and notification.
- Do not make breach conclusions alone.

## Healthcare-Specific Examples

- Ransomware encrypts a shared folder containing patient schedules: HIPAA review required because ePHI availability and confidentiality may be affected.
- `jane.smith` credentials are used from an unknown IP to access patient billing records: HIPAA review required.
- A phishing email is reported but no user clicked and no PHI was disclosed: document the event; breach notification may not be required.
- A workstation with cached patient documents runs malware: HIPAA review required.

## References

- HHS HIPAA Breach Notification Rule: <https://www.hhs.gov/hipaa/for-professionals/breach-notification/index.html>
- HHS Breach Reporting: <https://www.hhs.gov/hipaa/for-professionals/breach-notification/breach-reporting/index.html>
- HHS Security Rule Guidance: <https://www.hhs.gov/hipaa/for-professionals/security/guidance/index.html>

