# SOC-write-ups
# SOC Case Studies – Blue Team Investigations using Splunk & Wireshark

This repository contains hands-on cybersecurity investigations simulating real-world SOC workflows. Each write-up demonstrates detection, analysis, and response skills aligned with the MITRE ATT&CK framework, using industry-standard tools such as Splunk, Wireshark, and OSINT platforms.

## 🔍 Overview

These case studies reflect practical threat detection and investigation skills built through BTLO (Blue Team Labs Online), TryHackMe, and local Splunk environments. Each scenario includes:

- Log analysis and suspicious behavior detection
- MITRE ATT&CK mapping
- IOC development
- Risk evaluation and threat attribution
- Clear investigation steps and lessons learned

---

## 📝 Investigations

### 1. **Wireshark + OSINT: TrickBot & Cryptominer Traffic**
**Tools:** Wireshark, VirusTotal, Hybrid Analysis  
**Summary:** Multi-PCAP analysis of C2 activity, credential theft, and crypto-miner communication using ports 8000/8080. OSINT cross-referenced with IP reputation services to attribute malware families.

---

### 2. **Splunk Investigation: HR Department Compromise**
**Tools:** Splunk, Windows Event Logs (Event ID 4688)  
**Summary:** Identified LOLBin abuse and a typo-squatted user account within HR logs. Analysis showed credential impersonation, malicious downloads via certutil.exe, and mapping to ATT&CK TTPs.

---

## 🧠 Skills Demonstrated

- Log analysis & alert triage  
- MITRE ATT&CK correlation  
- Detection of credential abuse, LOLBins, and C2 traffic  
- SIEM queries and event filtering (Splunk SPL)  
- OSINT integration for IP/domain attribution  
- Structured reporting and written communication  

---

## 🎯 About Me

I’m an entry-level SOC Analyst focused on blue team operations, threat detection, and incident response. I’ve completed the Blue Team Level 1 certification (95%) and CompTIA Security+, with a strong practical foundation in SIEMs, PCAP analysis, and SOC workflows.

Feel free to connect or reach out — always happy to discuss blue team tactics or threat detection methods.

