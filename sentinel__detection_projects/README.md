# **Full-Stack Detection and Response with Microsoft Sentinel**

## **Overview**

This project simulates a progressive detection engineering and incident response workflow using Microsoft Sentinel. Spanning three phases - from baseline detection to triage of a chained attack, to SOAR-driven alert enrichment, it demonstrates the mindset and skillset required in a modern SOC environment.

Rather than showcasing one-off detections or synthetic labs, this project presents a structured progression:

* **Phase 1**: Lab configuration and Sentinel log ingestion.

* **Phase 2**: Foundational hands-on with Sentinel, raw log parsing, and alert building

* **Phase 3**: Multi-stage attack simulation and SOC-style investigation

* **Phase 4**: Enrichment and triage automation using SOAR workflows

This work is designed to reflect the tasks and thinking expected from a detection engineer or Level 1/2 SOC analyst—not a hobbyist or red teamer.

---

## **Repository Structure**

```
/sentinel-detection-project/
├── README.md                      # Project overview, objectives, skills demonstrated
├── phase1_lab_configuration.md      # Outline of the lab environment
├── phase2_procdump_detection/
│   ├── README.md                  # Baseline detection: Procdump → LSASS
│   └── detection.kql              # Raw KQL query for the rule
├── phase3_attack_chain/
│   ├── README.md                  # Multi-stage triage: Certutil → Schtasks → Procdump
│   └── detection.kql              # Detection logic used in investigation
├── phase4_regsvr32_soar/
│   ├── README.md                  # SOAR enrichment workflow: Regsvr32 + VirusTotal
│   ├── detection.kql              # Trigger rule for the Logic App
│   ├── logic_app_diagram.png      # Diagram of the SOAR branching logic
│   └── logicapp.json              # Logic App export (infrastructure-as-code)
```

---

## **Project Objectives**

* Develop high-signal, low-noise detections using KQL and MITRE mapping

* Simulate realistic post-exploitation scenarios involving credential dumping and persistence

* Apply SOC analyst triage methods to correlated alerts

* Build and document a full SOAR workflow that enriches alerts and supports automated triage

---

## **Key Capabilities Demonstrated**

| Phase | Focus | Core Skills |
| ----- | ----- | ----- |
| Phase 2 | Baseline Detection | KQL, log ingestion, XML parsing, simple rule tuning |
| Phase 3 | Kill Chain Triage | MITRE correlation, alert chaining, SOC workflows |
| Phase 4 | SOAR Enrichment Workflow | Logic App design, VirusTotal API, noise suppression |

Each write-up includes:

* Detection logic and rationale

* Analyst triage actions

* MITRE ATT\&CK mapping

* Reflection and opportunities for improvement

---

## **Tools and Technologies**

* Microsoft Sentinel (SIEM \+ SOAR)

* Azure Log Analytics (via Microsoft Monitoring Agent)

* Kusto Query Language (KQL)

* Logic Apps (SOAR automation)

* VirusTotal API (IP enrichment)

---

## **Skills Highlighted**

* Parsing and interpreting raw XML logs (Event ID 1\)

* Building detections mapped to MITRE TTPs

* Designing correlation-based triage workflows

* Using SOAR to enrich alerts and reduce false positives

* Handling real-world constraints like noisy data and incomplete telemetry

* Planning for alert fatigue and automation failure conditions

---

## **Lab Constraints and Assumptions**

This project prioritises realistic SOC workflows over red teaming or evasion. Some trade-offs:

* Used Microsoft Monitoring Agent (MMA) — no AMA or SecurityEvents (Event ID 4688\)

* No EDR or DNS telemetry — focused on process creation logs only

* IP-based enrichment only — file hash integration noted as future work

* All detections triggered in a safe, isolated lab VM

---

## **Future Improvements**

* Hash extraction and file reputation scoring

* Integration with Microsoft Defender for Endpoint

* Secondary enrichment source (e.g. AbuseIPDB) for fault tolerance

* Suppression logic for known-good behaviour

* MITRE coverage dashboard or visual heatmap

---

## **Summary**

This project demonstrates more than technical competence—it shows applied judgement. From initial detection through to automated triage and contextual enrichment, each component is built with operational reality in mind. The work reflects not just the ability to write queries, but the ability to think like a defender: detecting, correlating, and responding to adversary behaviour with clarity and control.
