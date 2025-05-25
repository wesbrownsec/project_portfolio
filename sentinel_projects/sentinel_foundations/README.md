# **Microsoft Sentinel Detection & Automation Project**

## **Overview**

This project was designed to simulate real-world SOC workflows using Microsoft Sentinel, enabling me to understand the end-to-end lifecycle of detection, triage, and automated enrichment. After completing more guided investigations, I wanted to independently build a realistic environment that mimicked the key elements of a modern SOC: telemetry ingestion, detection logic creation, alert tuning, and basic SOAR implementation. The project helped bridge the gap in foundational infrastructure knowledge that many analysts with a helpdesk background might already have, while also pushing deeper into security-specific tooling and reasoning.

## **Objectives**

This was more than a lab setup - it was a full learning environment aimed at:

* Gaining fluency in **KQL**, with an emphasis on parsing and filtering imperfect logs

* Building and tuning **custom detections** across a multi-stage attack chain

* Designing a realistic **SOAR automation** using Logic Apps and VirusTotal

* Thinking through **incident response logic**: what data matters, what to escalate, and what can be suppressed

* Simulating Tier 1/2 **SOC workflows** rather than simply running queries

## **Project Structure**

* **Phase 1:** Lab setup - VM configuration, log ingestion via MMA agent

* **Phase 2:** Initial single-stage detection using KQL

* **Phase 3:** Multi-stage attack simulation using LOLBins (e.g., `certutil`, `schtasks`, `procdump`), including custom detections and tuning

* **Phase 4:** SOAR enrichment - using Logic Apps to parse alert content, enrich with VirusTotal API, and tag severity for analyst consumption

This structure reflects my incremental learning approach, where each phase builds on the previous one and increases in complexity. While Phase 1 and 2 are basic, they lay the groundwork. Phases 3 and 4 focus on real detection engineering, triage thinking, and automation - the heart of modern SOC operations.

## **Key Tools & Techniques**

* **Microsoft Sentinel:** SIEM platform for ingestion, detection, and incident creation

* **KQL (Kusto Query Language):** Used to write all detections, including parsing raw XML for command-line activity

* **Logic Apps Designer:** Used to implement automation workflows, with branching logic and JSON-based parsing

* **VirusTotal API:** Used for IOC enrichment and severity tagging

* **Email Connector:** Configured to send enriched alerts to analysts with relevant fields (e.g., command line, parent process)

* **MMA Agent & VM Setup:** Simulated log ingestion from a Windows host with imperfect data

## **SOC-Relevant Workflows**

The following aspects of the project replicate common SOC analyst responsibilities:

* **Detection tuning**: Filtering benign uses of tools like `certutil`, `regsvr32`, and `procdump` based on context

* **Alert enrichment**: Using external threat intel (VirusTotal) to add decision-making context

* **False positive management**: Adjusting KQL filters to reduce noise and improve detection signal

* **Response classification**: Using Logic Apps to route alerts as either `ALERT` or `INFO` based on enrichment outcome

* **Incident simulation**: Correlating events across timestamps, users, and artifacts to simulate real-world triage

## **Lessons Learned**

* **Parsing challenges:** Raw XML logs required precise field extraction in KQL - a valuable skill when working with inconsistent data sources

* **Detection refinement:** My initial `procdump` query falsely relied on `lsass` appearing in command-line logs; had to update it after observing false negatives in scheduled task usage

* **Automation logic:** Logic Apps debugging taught me how to extract fields buried in nested alert payloads (e.g., `ExtendedProperties`) using both UI and code views

* **Analyst mindset shift:** This project forced me to think like an analyst - not just “what data can I extract,” but “why does this matter to triage?”

* **Solo blind spots:** Since I was testing my own alerts against my own attacks, I recognised the risk of blind spots and echo chambers - something I’d address with peer review in a real SOC

## **Summary**

This project isn't just about setting up a SIEM - it's about simulating the reality of security operations. From ingesting noisy logs to crafting high-fidelity alerts and enriching them with automation, I built a hands-on workflow that reflects actual Tier 1/2 SOC duties. Each step - from VM setup to email enrichment - pushed me to think operationally, not just technically.

