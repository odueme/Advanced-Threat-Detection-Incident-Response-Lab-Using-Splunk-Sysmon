# Detection Rule Documentation
## Registry Run Key Persistence — Behavioral Detection

**Rule ID:** DET-001  
**Rule Name:** Suspicious Registry Run Key Modification via PowerShell  
**Author:** Olayinka Oyetade  
**Date:** May 5, 2026  
**Severity:** HIGH  
**Status:** ACTIVE  

---

## 1. Rule Overview

### Purpose
Detects unauthorized modifications to Windows Registry Run keys used for persistence.

### What This Rule Detects
- PowerShell writing to Run keys
- Suspicious autorun registry entries
- Masqueraded key names (e.g., WindowsUpdate)

---

## 2. Data Requirements

| Requirement | Value |
|------------|------|
| SIEM | Splunk Enterprise |
| Data Source | Sysmon for Windows |
| Sysmon Version | v14+ |
| Sysmon Config | Event ID 13 enabled |
| Index | endpoint |
| Sourcetype | XmlWinEventLog:Microsoft-Windows-Sysmon/Operational |

---

## 3. Detection Queries

### Primary Query
```spl
index=endpoint EventCode=13 "powershell.exe" "CurrentVersion\Run"
| table _time, host, User, Image, TargetObject, Details
| sort -_time
```

### Broader Query
```spl
index=endpoint EventCode=13 
(TargetObject="*CurrentVersion\Run*" OR TargetObject="*CurrentVersion\RunOnce*")
| stats count by _time, host, User, Image, TargetObject, Details
| sort -_time
```

### Enriched Query
```spl
index=endpoint EventCode=13 
(TargetObject="*CurrentVersion\Run*" OR TargetObject="*CurrentVersion\RunOnce*")
| where NOT (Image="*msiexec.exe" OR Image="*setup.exe")
| eval risk_score=if(match(Image,"powershell|cmd|wscript|cscript"),80,40)
| table _time, host, User, Image, TargetObject, Details, risk_score
| sort -risk_score, -_time
```

---

## 4. Alert Configuration

| Setting | Value |
|--------|------|
| Alert Name | Suspicious Registry Run Key Modification |
| Schedule | Every 5 minutes |
| Trigger | Results > 0 |
| Action | Email alert |

---

## 5. Tuning Guidance

### Known False Positives

| Process | Reason | Action |
|--------|--------|--------|
| msiexec.exe | Installer behavior | Whitelist |
| setup.exe | Installer pattern | Whitelist |
| OneDrive.exe | Auto-start entry | Whitelist |
| Teams.exe | Auto-start | Whitelist |

---

## 6. Investigation Playbook

1. Verify alert
2. Check parent process
3. Check file existence
4. Review network activity
5. Determine scope

---

## 7. Rule Performance

| Metric | Value |
|-------|------|
| Detection Time | < 5 minutes |
| False Positives | Low |
| Coverage | T1547.001 |

