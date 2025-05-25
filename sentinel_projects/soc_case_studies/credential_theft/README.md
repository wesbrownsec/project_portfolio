## **Executive Summary**

A simulated intrusion was detected on a Windows host via Microsoft Sentinel, involving 11 security alerts. Analysis identified a successful attacker chain: download and execution of credential-dumping malware (procdump), privilege escalation, and persistence via registry RunKey. No evidence of data exfiltration was found, but privileged credentials were compromised. Immediate remediation and further investigation are recommended.

---

## **Alert Queue & Triage Table**

![Alert Queue](/sentinel_projects/soc_case_studies/credential_theft/screenshots/sentinel_alert_queue.PNG)

| Alert | Description | Severity | Initial Assessment |
| ----- | ----- | ----- | ----- |
| 154 | Registry RunKey Persistence | High | Rare in normal ops, likely attacker persistence (T1547.001) |
| 155 | Procdump.exe (lsass dump) | High | Cred dumping (T1003.001), major risk |
| 149 | Procdump.exe (notepad dump) | Medium | Likely tool testing, non-baseline process |
| 151 | Certutil.exe download | Medium | Suspicious, possible LOLBin malware ingress (T1105) |
| 150 | Certutil.exe encode (FP) | Medium | Benign admin task, confirmed by source/context |
| Other | Whoami, ipconfig, wmic, schtasks | Low | Recon commands—potentially attacker recon, context-dependent |

---

## **Attack Timeline**

* **13:00:11:** Attacker uses certutil to download procdump.exe from an external site.

* **13:02:27:** Attacker tests procdump by dumping notepad.exe (tool validation).

* **13:03:57:** Attacker uses procdump to dump lsass.exe, capturing privileged credentials.

* **13:06:25:** Attacker establishes persistence by creating a RunKey for procdump at system startup.

---

## **Investigation Steps / Evidence Review**

* **Certutil Download (Alert 151):**

  * *To confirm:* Review command-line logs for certutil usage with \-urlcache; check Sysmon Event ID 11 (FileCreate) to confirm file presence.

  * *Validation:* Compare the file hash of downloaded procdump.exe with official Sysinternals hash.

  * *Additional:* Check proxy/network logs for outbound connections to the download source.

![Certutil Alert](/sentinel_projects/soc_case_studies/credential_theft/screenshots/certutil_urlcache_alert_details.PNG)

* **Procdump Test (Alert 149):**

  * *To confirm:* Examine process creation logs for procdump.exe targeting notepad.exe. Confirm creation and quick deletion of notepad.dmp (Event ID 4660).

  * *Rationale:* Tool testing is a common attacker TTP to evade controls or test permissions.

![Procdump test Alert](/sentinel_projects/soc_case_studies/credential_theft/screenshots/procdump_notepad_alert_details.PNG)

* **Procdump LSASS Dump (Alert 155):**

  * *To confirm:* Search process creation logs for procdump.exe with \-ma lsass.exe; validate presence and integrity of lsass\_dump.dmp in filesystem logs.

  * *Check for exfiltration:* Review recent network traffic for potential transfer of lsass\_dump.dmp.

![Procdump lsass Alert](/sentinel_projects/soc_case_studies/credential_theft/screenshots/procdump_lsass_alert_details.PNG)

* **Registry Persistence (Alert 154):**

  * *To confirm:* Query endpoint event logs for new/modified RunKey entries in HKCU/HKLM for procdump.exe.

  * *Verify persistence:* Review boot sequence logs for procdump.exe launches after registry change.

![registry key Alert](/sentinel_projects/soc_case_studies/credential_theft/screenshots/registry_persistance_alert_details.PNG)

* **Certutil Encode (Alert 150):**

  * *To confirm FP:* Review command-line arguments (-encode), file types, user context, and origin system. Confirm admin workstation, expected activity pattern.

* **Recon/Info-Level Alerts:**

  * *To confirm:* Review user context, process lineage, and sequence of commands (whoami/ipconfig) to assess whether these indicate normal admin tasks or attacker recon.

* **Lateral Movement:**

  * *Next step:* Search authentication and network logs for any use of compromised credentials elsewhere.

---

## **Findings**

* Attacker gained access to a privileged/admin account (“redteam”). Initial access vector undetermined—further review of user activity/logins is needed.

* Attacker performed local recon (whoami, ipconfig), then used certutil.exe to ingress procdump.exe (LOLBas).

* Procdump was tested on notepad.exe, then used to dump lsass.exe. Resulting credential dump was saved to C:\\Windows\\Temp\\lsass\_dump.dmp, deleted notepad.dmp for OPSEC.

* Registry persistence was established (RunKey), ensuring procdump would persist on reboot.

* No signs of data exfiltration or lateral movement found, but privileged credentials are compromised.

* All malicious actions occurred within 6 minutes, indicating a fast and efficient attacker workflow.

---

## **Remediation & Recommendations**

* **Immediate isolation** of the compromised host from the network and internet.

* **Remove procdump.exe** and any unauthorized binaries from the system.

* **Delete lsass\_dump.dmp** and any other suspicious files.

* **Remove registry RunKey** entries associated with persistence.

* **Reset passwords** for affected privileged accounts (“redteam”), force reauthentication.

* **Review and harden LOLBin (certutil) use:** Consider restricting \-urlcache flag via AppLocker/SRP, or alert on suspicious usage patterns.

* **Review EDR whitelisting** for procdump, update controls as needed.

* **Hunt for lateral movement:** Search authentication/network logs for further compromise.

* **User awareness training:** Brief admins on LOLBin abuse and credential hygiene.

* **Update detection rules** for this attack chain, including procdump, certutil, and registry modifications.

* **Monitor for recurrence**: Continue surveillance for similar attacker behaviors or recurrence of indicators.

* **Escalate to IR team**: Due to compromise of admin credentials and persistence, initiate full IR if further evidence emerges.

---

## **MITRE ATT\&CK Mapping**

| Tactic | Technique | Example |
| ----- | ----- | ----- |
| Persistence | T1547.001 (Registry Run Key) | procdump.exe in HKCU Run |
| Credential Access | T1003.001 (LSASS Dump) | procdump.exe \-ma lsass.exe |
| Defense Evasion | T1036 (Masquerading) | Use of LOLBins, file deletion |
| Execution | T1105 (Ingress Tool Transfer) | certutil.exe download |
| Discovery | T1087 (Account Discovery), T1016 (System Network Configuration Discovery) | whoami, ipconfig |

---

*Author’s Note*

This investigation was performed in a home lab environment, utilizing a single Windows endpoint as the victim system. Due to the limited scope and volume of activity in the lab, the detection logic implemented in Microsoft Sentinel leveraged broad KQL queries designed to capture a wide range of events (e.g., process creation, file modification, registry changes, LOLBin usage) with minimal filtering.

In an enterprise SOC setting, detection content would typically be far more granular and context-specific, correlating telemetry across multiple hosts, user accounts, and network segments. Playbooks would leverage asset baselining, alert suppression logic, and advanced correlation to minimize false positives and prioritize high-fidelity detections.

The investigative process documented here reflects best practices for incident triage, validation, and response. However, due to the controlled lab environment, some investigative steps (such as comprehensive lateral movement hunting or deep network forensics) were either simulated or described as “recommended steps,” rather than executed with live data.

If required, I can provide example KQL detection rules used in this investigation, discuss how these would be adapted for a production environment, or elaborate on ways to scale detection and response in larger organizations.
