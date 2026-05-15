# Incident Report
## SOC Home Lab — Simulated Threat Detection Exercise

**Report ID:** IR-2026-001  
**Classification:** CONFIDENTIAL — INTERNAL USE ONLY  
**Date:** May 5, 2026  
**Analyst:** Odueme Uzoezi Francis  
**Severity:** HIGH  
**Status:** RESOLVED  

---

## 1. Executive Summary
A simulated persistence attack was executed against a controlled Windows 10 endpoint. A malicious registry Run key was created to execute `malware.exe` on login. Detection was achieved via Sysmon (Event ID 13) and Splunk within 5 minutes.

---

## 2. Incident Timeline

| Time | Event |
|------|------|
| T+00:00 | PowerShell command executed |
| T+00:01 | Sysmon logs registry modification |
| T+00:02 | Splunk ingests logs |
| T+00:04 | Detection rule triggered |
| T+00:05 | Alert sent |
| T+00:07 | Incident confirmed |

---

## 3. Attack Description

### Command Executed
```powershell
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
-Name "WindowsUpdate" `
-Value "C:\Users\Public\malware.exe" `
-PropertyType String `
-Force
```

---

## 4. Detection

### Detection Details

| Field | Value |
|------|------|
| Detection Tool | Splunk |
| Data Source | Sysmon |
| Event ID | 13 |
| Index | endpoint |

---

### Detection Query
```spl
index=endpoint EventCode=13 "powershell.exe" "CurrentVersion\Run"
| table _time, host, User, Image, TargetObject, Details
| sort -_time
```

---

## 5. MITRE ATT&CK Mapping

| Field | Value |
|------|------|
| Tactic | Persistence |
| Technique | T1547.001 |
| Platform | Windows |

---

## 6. Impact Assessment

| Category | Impact |
|----------|--------|
| Confidentiality | HIGH |
| Integrity | HIGH |
| Availability | MEDIUM |

---

## 7. Remediation

- Remove registry key
- Reset credentials
- Scan system

---

## 8. Analyst Notes
This simulation confirmed that behavioral detection (catching the action of writing to a Run
key) is more reliable than signature-based detection (trying to identify the specific malware
file). The detection fired regardless of the filename or payload — it detected the attacker
behavior, not the specific tool, which makes it significantly harder to evade.
