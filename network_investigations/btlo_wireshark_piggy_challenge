**Wireshark \+ OSINT Investigation: TrickBot & Cryptominer Traffic (BTLO Piggy Challenge)**
*A multi-phase malware investigation using Wireshark, VirusTotal & Hybrid Analysis.*

---

### **🔍 Summary**

This investigation combines Wireshark packet analysis with open-source intelligence (OSINT) to trace potential malware activity across three packet captures. The exercise spanned SSH data transfers, behavioral profiling, and the attribution of IP addresses to known malware families including TrickBot and cryptominers.

---

### **🔍 Key Findings**

* **SSH Transfer Detection:** Identified SSH-based data exfiltration between internal IP `10.0.9.171` and a remote host.

* **TrickBot Infrastructure:** Confirmed presence of TrickBot-linked C2 IPs using VirusTotal and Hybrid Analysis.

* **Cryptominer Behavior:** Flagged persistent communication over ports 8000/8080 as linked to crypto-mining operations.

* **C2 Behavior:** Traffic patterns matched MITRE ATT\&CK's web-based command and control activity.

---

### **🛠️ Investigation Steps**

#### **1\. PCAP One: SSH Data Transfer**

**Wireshark Filter**:

tcp.port \== 22

* Internal IP `10.0.9.171` initiated an SSH session.

* Verified directionality via TCP stream and endpoint roles.

#### **2\. PCAP One: Data Volume Analysis**

**Wireshark View**:

* Navigated to: `Statistics > Conversations`

* Total data transferred: **1131MB** across SSH sessions.

#### **3\. PCAP Two: TrickBot Attribution**

**Observed IPs**:

* `188.120.241.27`

* `195.161.41.93`

* `92.53.67.7`

* `31.184.253.37`

* `78.155.206.172`

**OSINT Evidence**:

* **VirusTotal**: Multiple IPs showed high detection rates.

* **Hybrid Analysis**:

  * - Malicious PowerShell + batch script spawning miner payloads (T1059, T1053)

  * C2 beaconing to known TrickBot domains (T1071.001)

**Risk**: Credential theft → Lateral movement → Ransomware deployment.

#### **4\. PCAP Three: Suspicious Port Behavior**

**Filter Used**:

tcp.port \== 8000 || tcp.port \== 8080

* Two outbound connections stood out:

  * `104.236.57.24` on port **8000**

  * `192.233.171.171` on port **8080**

**ASN Resolution**:

* Queried both IPs via VirusTotal and IPinfo to confirm reputational flags.

#### **5\. PCAP Three: Cryptominer Attribution**

**OSINT Findings**:

* **VirusTotal**: Community comments on `104.236.57.24` associated with miner activity.

* **Hybrid Analysis**:

  * Mining process caused CPU usage spikes over 90%

  * Persistence via scheduled task and registry keys

**Risk**: CPU exhaustion → degraded performance → masked secondary payloads.

#### **6\. MITRE ATT\&CK Mapping**

| Tactic             | Technique      | Relevant Activity                     |
|:-------------------|:---------------|:--------------------------------------|
| Command & Control  | T1071.001       | HTTP C2 over port 8000 and 8080        |
| Credential Access  | T1555           | TrickBot credential theft modules     |
| Defense Evasion    | T1055 / T1059    | TrickBot process spawning              |
| Impact             | T1496           | CPU hijacking from mining              |

---

### **🔥 Risk Implications**

* **TrickBot**:

  * Known for credential theft (T1555), ransomware delivery (T1486), and lateral movement via SMB (T1021.002).

  * Can result in total domain compromise and financial loss.

* **Cryptominers**:

  * Drain system resources (T1496), creating stealth for follow-up attacks.

  * Commonly deployed alongside or as decoys for APT toolkits.

---

### **💡 Lessons Learned**

* **OSINT Validation is Crucial**: Attribution and risk classification are strengthened through multi-source OSINT.

* **Wireshark Alone is Not Enough**: Behavioral validation and technique mapping require external context.

* **Attention to Anomalies Pays Off**: Low-traffic, high-port-number communication often indicates hidden behaviors.

---

This challenge tested not just technical analysis skills, but also an analyst’s ability to contextualize traffic in the broader cyber threat landscape. It reinforces how layered tooling (packet analysis \+ OSINT \+ ATT\&CK) enables deeper detection, response, and threat attribution in SOC environments.
