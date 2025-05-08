**Procdump Detection – Initial Hands-on with Sentinel (T1003.001)**

This was my first hands-on experience building a detection rule in Microsoft Sentinel. Although I had prior exposure to SIEMs through Splunk, Sentinel presented a different workflow, particularly around log normalization, alert configuration, and entity mapping. My aim here wasn’t to produce a complex detection, but rather to **get familiar with the platform**, understand the ingestion and query flow, and successfully create an alert end-to-end.

---

**Objective**

To simulate a simple but realistic post-exploitation technique — credential dumping from lsass.exe using procdump.exe — and build a custom detection in Sentinel using raw event logs. This attack corresponds to **MITRE ATT\&CK T1003.001: OS Credential Dumping – LSASS Memory**.

---

**Detection Logic**

I used the Microsoft Monitoring Agent (MMA) to collect logs, which are ingested as raw XML into the Event table (as schema-less Event ID 1 process creation logs). Key fields were extracted using extract() within KQL to parse:

* Image  
* CommandLine  
* ParentImage  
* User

The rule searches for executions of procdump.exe with command-line arguments referencing lsass, a strong indicator of credential dumping.

kql

CopyEdit

Event

| where EventID \== 1

| extend raw\_xml \= tostring(EventData)

| extend

	Image \= extract(@"\<Data Name=""Image""\>(.\*?)\</Data\>", 1, raw\_xml),

	CommandLine \= extract(@"\<Data Name=""CommandLine""\>(.\*?)\</Data\>", 1, raw\_xml),

	ParentImage \= extract(@"\<Data Name=""ParentImage""\>(.\*?)\</Data\>", 1, raw\_xml),

	User \= extract(@"\<Data Name=""User""\>(.\*?)\</Data\>", 1, raw\_xml)

| where Image has "procdump" and CommandLine has "lsass"

| project TimeGenerated, Image, CommandLine, ParentImage, User

---

**Sentinel Rule Configuration**

* **Schedule**: Every 5 minutes (15-minute lookback)  
* **Severity**: High  
* **Tactic**: Credential Access  
* **Trigger Threshold**: \> 0 results  
* **Incident Creation**: Enabled

Credential dumping is often performed quickly during post-exploitation, so a short lookback interval was chosen to minimize alert latency. Since legitimate use of procdump against lsass.exe is virtually nonexistent in production environments, the rule is tuned for **high signal and low false positives**.

---

**Analyst Response Plan (Hypothetical)**

If this alert fires in a live environment, triage steps might include:

* Confirming execution context (e.g., domain user vs SYSTEM)  
* Searching for .dmp files on disk  
* Investigating related activity (e.g., PsExec, PowerShell, or scheduled tasks)  
* Checking for outbound data transfer  
* Containment steps: isolate host, disable compromised accounts, reset affected credentials

---

**Outcome**

This rule successfully triggered after simulating a credential dump in my VM using procdump.exe. It validated that my **event ingestion, parsing logic, and alert configuration** were functional — giving me a working baseline to build more advanced detections in later projects.

 
