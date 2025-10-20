# **Phase 3 – Multi-Stage Attack Detection (Microsoft Sentinel)**

## **Overview**

This phase focused on simulating a realistic, multi-stage attack using native Windows tools to reflect a common post-compromise scenario in enterprise environments. The goal was to:

* Simulate attacker activity using LOLBins (Living Off the Land Binaries)

* Create custom KQL detections across each stage of the attack

* Extract and enrich relevant fields for triage

* Tune detections to reduce false positives and negatives

* Correlate alerts across time, user, and system context

Compared to Phase 2's single-stage detection, this phase introduced correlation logic and higher fidelity filtering to better reflect actual SOC workflows.

## **Simulated Attack Chain**

A three-stage attack chain was executed:

1. **Command & Control**

   * `certutil.exe` used to download `procdump.exe` from internal host

   * **MITRE T1105 – Ingress Tool Transfer**
  
   * [Certutil Use alert](/sentinel_projects/sentinel_foundations/phase3_attack_chain/screenshots/certutil_alert.PNG)

2. **Persistence**

   * A scheduled task created via `schtasks.exe` to launch `procdump.exe` at user login

   * **MITRE T1053.005 – Scheduled Task / Job: Logon Trigger**

    * [Malicious Scheduled Task alert](/sentinel_projects/sentinel_foundations/phase3_attack_chain/screenshots/malicious_scheduled_task.PNG)

3. **Credential Dumping**

   * On next login, `procdump.exe` dumps LSASS memory

   * **MITRE T1003.001 – OS Credential Dumping: LSASS Memory**

    * [Credential Dumping alert](/sentinel_projects/sentinel_foundations/phase3_attack_chain/screenshots/credential_dumping_alert.PNG)

Each stage was logged via process execution events (Event ID 1), parsed from raw XML in Sentinel, and detected via tailored KQL queries.

## **Detection Logic**

All detections were built using manual parsing of XML fields from `EventData`, using regular expressions to extract key elements (Image, CommandLine, ParentImage, User, IntegrityLevel).

### **`certutil` Detection**

* **Initial Logic**: Match on Image field containing `certutil`

* **Tuning**: Added filter on CommandLine containing `http` to detect outbound transfer activity and reduce false positives

* **Key Fields for Correlation**: `User`, `TimeGenerated`, `IntegrityLevel`

### **`schtasks` Detection**

* **Initial Logic**: Match on Image containing `schtasks.exe`

* **Tuning**: Added filter for ParentImage (`powershell.exe`, `cmd.exe`) and CommandLine (`create`) to isolate suspicious task creation from legitimate system behaviour

* **Key Fields for Triage**: `CommandLine`, `ParentImage`, `User`

### **`procdump` Detection**

* **Initial Logic**: Match on Image containing `procdump`, and CommandLine containing `lsass`

* **Tuning**: Removed `lsass` requirement after discovering that scheduled task execution didn’t include it in CommandLine, which caused false negatives

* **Tradeoff**: Broader detection increased false positive risk slightly, but use of `procdump` remains rare and high risk, justifying wider scope

## **Analyst Perspective & Reasoning**

* **Prioritisation**: All three detections were evaluated for context and privilege level. `procdump` was weighted highest due to credential access.

* **Suppressions**: Scheduled task alerts required tuning to avoid system noise; benign uses by administrators may require whitelisting in production.

* **Escalation Criteria**: Any alert for `procdump` execution under elevated integrity was considered high severity.

## **Response Workflow (Simulated Triage)**

If all three alerts fired:

1. **Certutil**: Check outbound IP, validate download behaviour, run IOC through VirusTotal

2. **Scheduled Task**: Confirm creation time, verify user, list existing tasks

3. **Procdump**: Investigate for LSASS dump artifacts, correlate with login events, assess exfiltration potential

## **Technical Constraints & Workarounds**

* **Log Gaps**: No security logs available (e.g., 4624 for logon, 4698 for task creation), which limited correlation depth

* **Raw XML Parsing**: Required custom KQL parsing via regex to extract fields, increasing query complexity

* **Detection Blind Spots**: Initial detection logic for `procdump` was too narrow - fixed via broader CommandLine coverage

## **Lessons Learned**

* **Detection tuning is non-trivial**: Even small context changes (scheduled task vs manual execution) can break alerts

* **Real logs are messy**: Event content varies and requires flexible parsing strategies

* **Correlation is key**: Individual alerts mean little without context - timestamps, user, and integrity level matter

* **Thinking like an analyst**: This phase forced me to consider what information actually aids triage - not just what can be logged

## **Improvements for Real SOC Use**

* Add more log sources (e.g., file creation, task modification, logon events)

* Use IntegrityLevel to drive SOAR severity tiering (e.g., low/medium/high)

* Extract contacted IP and downloaded file from `certutil`, enrich via VirusTotal automatically

* Expand parent-child process chain tracking to confirm abuse patterns

---

This phase represents a major shift from basic detection to true incident simulation. This phase simulated the kind of detection refinement process common in Tier 1–2 SOC environments.
