# **Day 1: Lab Environment and Logging Setup**

## **Overview**

Before developing detections or response workflows, I built a dedicated lab environment to simulate post-exploitation behaviour, collect relevant telemetry, and validate end-to-end visibility within Microsoft Sentinel. This setup prioritised simplicity, repeatability, and operational realism — not full-scale emulation or red teaming.

The goal was to simulate **realistic attacker behaviour using native Windows tools**, ingest those events into Sentinel, and use them to construct high-signal, actionable detections and response workflows.

---

## **Virtual Machine Setup**

* **Host:** Local laptop (Windows 11\)

* **Hypervisor:** VirtualBox

* **Guest OS:** Windows 10 Pro (x64)

* **Configuration:**

  * Clean Windows install (baseline snapshot taken post-setup)

  * Local administrator user for simulations (`redteam`)

  * No domain controller or segmentation — single-host lab

---

## **Log Ingestion and Agent Configuration**

* **Agent:** Microsoft Monitoring Agent (MMA)

* **SIEM:** Azure Log Analytics Workspace (connected to Sentinel)

* **Connection:** MMA configured with workspace ID and key

* **Validation:**  
   Successful ingestion confirmed using test queries:
 
  `Event | take 10`

---

## **Logging Sources Used**

| Source | Description |
| ----- | ----- |
| **Event Log** | Logs ingested into the `Event` table via MMA |
| **Sysmon (partial)** | Sysmon process creation logs (Event ID 1\) were generated locally but parsed manually due to schema limitations |
| **Raw XML Extraction** | All field data (e.g., `Image`, `CommandLine`, `ParentImage`) was parsed manually from `EventData` using `extract()` |

---

## **Key Characteristics of the Logging Pipeline**

* All detections are based on **Event ID 1-style process creation logs**

* Logs were ingested via MMA into the unstructured `Event` table

* The environment **did not use** schema-based tables like `SysmonEvent` or `SecurityEvent`

* **All field-level data** (e.g., `Image`, `CommandLine`, `ParentImage`, `User`) was extracted using regular expressions

* **No native PowerShell logs**, **task scheduler events**, or **4688-style Security events** were available

---

## **Known Limitations**

This lab environment was intentionally minimal, with the following constraints:

* **No SecurityEvent ingestion**, and therefore:

  * No `Event ID 4624` (logons)

  * No `Event ID 4688` (Security log process creation)

* **No PowerShell logging** (e.g., script block or module logs)

* **No Task Scheduler logs** (e.g., Event ID 106 or 200 series)

* **No DNS, firewall, or EDR telemetry**

* **No schema-based SysmonEvent table** — all events were extracted from raw XML

* **No cloud, identity, or authentication logs (AAD, Office365)**

---

## **Design Rationale**

This lab was built to reflect a lightweight but realistic defensive environment where:

* Detection is based on raw logs, not curated datasets

* Events are ingested in an unstructured format requiring custom parsing

* Only process creation and ancestry are available for logic-building

This prioritises **log comprehension, data extraction, and high-signal rule design** over breadth of telemetry.

---

## **Outcome**

This setup enabled:

* Realistic simulation of native attacker techniques (e.g., credential dumping, LOLBAS abuse)

* Manual field extraction and rule development using KQL and regex

* Design and testing of detection and SOAR workflows within a constrained telemetry environment

The resulting detections were designed to operate **under imperfect visibility** — a valuable skill in both budget-constrained SOCs and real-world response scenarios.
