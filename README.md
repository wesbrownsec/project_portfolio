# Wesley Brown | SOC Analyst Portfolio

This portfolio showcases my practical experience in threat detection, incident response, and adversary tradecraft analysis. All investigations replicate real-world SOC workflows using Splunk, Microsoft Sentinel, Wireshark, and OSINT platforms. Projects are organised by technical complexity, starting from foundational log triage to advanced detection engineering and SOAR automation.

---

## Featured Projects (Organised by Technical Depth and Impact)

### 1. Microsoft Sentinel SOAR Workflow – Regsvr32 Abuse and Alert Enrichment
**Platform:** Microsoft Sentinel and Logic Apps  
**Focus:** Detection Engineering and Automation  
**Skills:** KQL, MITRE T1218.010, API integration (VirusTotal), SOAR logic  
**[Write-up →](/sentinel__detection_projects/phase4_regsvr32_soar/README.md)**

- Developed a full SOAR pipeline for detecting regsvr32 abuse with integrated alert enrichment using VirusTotal.
- Designed branching logic to escalate only high-confidence alerts, reducing false positives and analyst workload.
- Emphasised contextual decision-making and automation reflecting real SOC pain points.

---

### 2. Sentinel Detection Chain – Credential Dumping via LOLBins
**Platform:** Microsoft Sentinel  
**Focus:** Multi-stage Attack Simulation  
**Skills:** Custom KQL detections, MITRE T1003.001, T1053.005, T1105  
**[Write-up →](/sentinel__detection_projects/phase3_attack_chain/README.md)**

- Simulated an end-to-end attack chain using certutil for tool download, schtasks for persistence, and procdump for LSASS dumping.
- Created individual detections for each stage and manually correlated them into a single incident timeline.
- Demonstrated realistic detection logic and alert chaining, aligned with analyst workflows.

---

### 3. BOTS v1 Investigation – Multi-Stage Compromise Analysis
**Platform:** Splunk with Sysmon logs and VirusTotal  
**Focus:** Full-Spectrum SOC Investigation  
**Skills:** SPL, IOC enrichment, MITRE ATT&CK mapping, infrastructure attribution  
**[Write-up →](/splunk_investigations/botsv1_investigation/botsv1_compromise_analysis.md)**

- Investigated a simulated attack involving vulnerability scanning, brute-force login, malware upload, and host compromise.
- Mapped attacker actions to MITRE stages and used OSINT tools to trace external infrastructure.
- Showcased complete incident reconstruction with evidence, artefact linkage, and clear defensive takeaways.

---

### 4. BTLO Wireshark and OSINT Investigation – TrickBot and Cryptominer Traffic
**Platform:** Wireshark and Hybrid Analysis  
**Focus:** Network Forensics and Threat Attribution  
**Skills:** PCAP analysis, malware attribution, MITRE mapping  
**[Write-up →](network_investigations/btlo_wireshark_piggy_challenge.md)**

- Analysed multi-PCAP dataset for outbound SSH exfiltration and suspicious C2 traffic.
- Identified TrickBot and cryptominer infrastructure using external validation.
- Mapped observed behaviour to techniques such as credential theft, resource hijacking, and HTTP-based C2.

---

### 5. HR Department Compromise – Internal Threat Investigation
**Platform:** Splunk  
**Focus:** Insider Threat and Credential Abuse  
**Skills:** Windows Event ID analysis, user baseline profiling, MITRE T1078.004, T1105  
**[Write-up →](splunk_investigations/thm_hr_department_compromised.md)**

- Investigated suspicious process execution and a typo-squatted user account mimicking a legitimate employee.
- Detected use of certutil.exe to download remote payloads, suggesting abuse of built-in Windows tools (LOLBins).
- Applied user activity baselining and detection logic for low-and-slow internal compromise scenarios.

---

## Core Skills Demonstrated

- Detection engineering in Splunk (SPL) and Microsoft Sentinel (KQL)
- SOC-style alert triage, incident reconstruction, and correlation
- Application of the MITRE ATT&CK framework to adversary techniques
- Integration of external threat intelligence sources (VirusTotal, Hybrid Analysis)
- Construction of low-noise, high-context detection logic
- Practical use of SOAR workflows for enrichment and automated triage

---

## About Me

I am an entry-level SOC analyst with strong practical skills in detection, investigation, and alert triage. I hold certifications in **Blue Team Level 1 (95%)** and **CompTIA Security+**, and have built a portfolio grounded in realistic adversary behaviours and end-to-end detection logic. My approach is grounded in evidence, context, and analyst-ready reporting.


---

