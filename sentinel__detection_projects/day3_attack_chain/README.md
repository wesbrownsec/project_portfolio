# **Day 3: Simulated Incident – Credential Dump via LOLBins and Scheduled Task**

---

**Executive Summary**

This simulated incident demonstrates a chained attack scenario where an adversary uses native Windows binaries to download a credential dumping tool, persist it via a scheduled task, and execute it at logon. The aim is to mimic low-sophistication, high-success-rate post-exploitation tradecraft — and simulate how a SOC analyst would detect, investigate, and respond to it.

---

**Incident Overview: Attacker Behaviour**

| Step | Adversary Action | MITRE Technique |
| :---- | :---- | :---- |
| 1 | Used certutil.exe to download procdump.exe from an internal IP | T1105 – Ingress Tool Transfer |
| 2 | Created a scheduled task to launch procdump.exe at logon | T1053.005 – Scheduled Task |
| 3 | On next login, the task executed, and procdump.exe dumped LSASS memory | T1003.001 – Credential Dumping (LSASS) |

This pattern reflects a common kill chain used in real environments where:

* Admin tools are abused for stealth  
* Persistence is automated  
* Credential harvesting is delayed until reentry (e.g., next login)

---

**Detection Timeline**

| Time | Alert | Description |
| :---- | :---- | :---- |
| 10:12 | Certutil Download Detected | Tool transfer from 192.168.1.80 to local host |
| 10:29 | Scheduled Task Created | Persistence setup to trigger payload |
| 10:39 | Procdump Executed | Task fired post-login, indicating successful credential access |

---

**Alert 1: Tool Ingress via certutil.exe (T1105)**

**What Happened**:  
 The attacker used certutil.exe to fetch procdump.exe from a remote host over HTTP.

**Why It Mattered**:  
 This is a high-signal behaviour. certutil is rarely used interactively, especially by users without admin context. Its use suggests deliberate staging.

**Analyst Action**:

* Check user identity (redteam) and logon source  
* Use VirusTotal or internal IOC sources to assess 192.168.1.80  
* Confirm file write activity (e.g., was procdump.exe saved to disk?)

---

**Alert 2: Scheduled Task Creation via schtasks.exe (T1053.005)**

**What Happened**:  
 Roughly 15 minutes later, the attacker created a scheduled task using schtasks.exe, launched from PowerShell.

**Why It Mattered**:  
 This shows intent to persist the payload beyond the current session — a classic lateral movement and privilege escalation setup.  
 It was executed from a shell (not a system task or installer), increasing suspicion.

**Analyst Action**:

* Review task name and command path  
* Confirm user context and whether UAC bypass was attempted  
* Look for other tasks created during the session  
* Cross-reference logon ID if available

---

**Alert 3: Procdump Execution Triggered (T1003.001)**

**What Happened**:  
 At next logon, the scheduled task executed procdump.exe. It did **not** contain lsass in the command line — suggesting obfuscation or indirection.

**Why It Mattered**:  
 Dumping LSASS without direct command-line indicators is a real-world tactic used to bypass basic rules. This required correlation with previous steps to confirm malicious behaviour.

**Analyst Action**:

* Confirm creation of .dmp files (e.g., C:\\Users\\...\\procdump.dmp)  
* Inspect outbound traffic (did anything attempt to exfil data?)  
* Check process ancestry — was procdump launched by a system process?

---

**Analyst Conclusion**

This incident reflects **intentional attacker movement across the kill chain**:

* Stage → Persist → Harvest  
* Tools: Native binaries (certutil, schtasks, procdump)  
* Strategy: Minimal direct indicators, maximum plausible deniability

Even though each action could be benign in isolation, **correlation and timing** show that:

* The same user (redteam) performed each action  
* Each alert aligns with expected attacker logic  
* No system maintenance or admin tooling justifies this pattern

---

**Outcome**

All three custom Sentinel rules triggered successfully and were **manually correlated** into a single incident.

This simulation demonstrated:

* High-signal detections using minimal tuning  
* Attacker behavior across MITRE stages  
* Triage workflows matching realistic SOC escalation paths

 
