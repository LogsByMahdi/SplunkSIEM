# SplunkSIEM – My Home SOC Lab Project

## Overview
I built this lab to sharpen my SOC analyst skills and show how I can set up, run, and get value out of a SIEM.  
The project walks through building a Splunk server on Ubuntu, pulling in logs from a Windows VM (including Sysmon logs), and then turning that data into detections, dashboards, and incident reports.

I treated this like a real SOC environment – from configuring log sources to actually detecting simulated attacks and writing up my findings.

## Lab Setup
**Environment:**
- Splunk Enterprise 9.4.3 running on Ubuntu 24.04 (VirtualBox)
- Windows 10 Pro VM with:
  - Splunk Universal Forwarder
  - Sysmon (with SwiftOnSecurity config)
- Both VMs on a bridged network for direct communication

**Data sources I ingested into Splunk:**
- Windows Security Event Logs
- Sysmon Operational Logs
- Process creation (Event ID 1)
- Network connections (Event ID 3)
- Failed login attempts (Event ID 4625)

---

**Flow:**
1. Windows VM generates logs (Sysmon + Event Viewer)
2. Splunk Universal Forwarder sends them over port 9997
3. Splunk indexes and stores the events
4. Searches, dashboards, and alerts built from the indexed data

---

## Detection Queries

### Suspicious PowerShell Usage
```spl
index=* sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
| search Image="*powershell.exe*" OR CommandLine="*powershell*"
| table _time user CommandLine
