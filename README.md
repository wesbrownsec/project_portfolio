# SOC-write-ups

## SOC Case Studies – Blue Team Investigations using Splunk & Wireshark

This repository contains hands-on cybersecurity investigations simulating real-world SOC workflows. Each write-up demonstrates detection, analysis, and response skills aligned with the MITRE ATT&CK framework, using industry-standard tools such as Splunk, Wireshark, and OSINT platforms.

---

## Overview

These case studies reflect practical threat detection and investigation skills built through BTLO (Blue Team Labs Online), TryHackMe, and local Splunk environments. Each scenario includes:

- Log analysis and suspicious behaviour detection
- MITRE ATT&CK mapping
- IOC development
- Risk evaluation and threat attribution
- Clear investigation steps and lessons learned

---

## Investigations

### 1. **Splunk Investigation: Corporate Web Server Attack (BOTS v1)**
- **Tools:** Splunk, Windows Event Logs (Event ID 1, 4625, 4688), VirusTotal
- **Summary:** 
  - Full multi-stage investigation based on BOTS v1 data.
  - Tracked external brute-force login attempts, credential abuse, malware execution (3791.exe), and C2 communication over HTTP.
  - Built clear attack chain mapping (Initial Access → Credential Access → Execution → Persistence → C2).
  - Detailed MITRE ATT&CK mapping, artefact extraction, IOC development, and structured evidence linking.
- **Notes:**  
  This case study reflects the strongest depth of detection, analysis, and reporting, showcasing advanced Splunk searching, IOC enrichment, and adversary activity tracking.

---

### 2. Wireshark + OSINT: TrickBot & Cryptominer Traffic
- **Tools:** Wireshark, VirusTotal, Hybrid Analysis
- **Summary:** 
  - Multi-PCAP analysis of C2 activity, credential theft, and crypto-miner communication using ports 8000/8080.
  - OSINT cross-referenced with IP reputation services to attribute malware families.

---

### 3. Splunk Investigation: HR Department Compromise
- **Tools:** Splunk, Windows Event Logs (Event ID 4688)
- **Summary:** 
  - Identified LOLBin abuse and a typo-squatted user account within HR logs.
  - Analysis showed credential impersonation, malicious downloads via certutil.exe, and mapping to ATT&CK TTPs.

---

## Skills Demonstrated

- Log analysis & alert triage
- MITRE ATT&CK correlation
- Detection of credential abuse, LOLBins, malware, and C2 traffic
- SIEM queries and event filtering (Splunk SPL)
- OSINT integration for IP/domain attribution
- Structured investigation writing and professional reporting

---

## About Me

I’m an entry-level SOC Analyst focused on blue team operations, threat detection, and incident response.  
I’ve completed the **Blue Team Level 1 (BTL1)** certification (95%) and **CompTIA Security+**, with a strong practical foundation in:

- SIEM (Splunk) threat hunting
- PCAP analysis
- Endpoint artefact investigation
- Threat detection workflows

Feel free to connect or reach out — always happy to discuss blue team tactics or threat detection methods.
