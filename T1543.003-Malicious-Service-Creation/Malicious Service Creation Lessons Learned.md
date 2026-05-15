# Detection Rule Documentation  
## Malicious Windows Service Creation — Persistence Detection  

**Rule ID:** DET-2026-003  
**Rule Name:** Suspicious Windows Service Creation via sc.exe  
**Date Created:** May 13, 2026  
**Author:** Odueme Uzoezi Francis  
**Severity:** HIGH  
**Status:** ACTIVE  
**MITRE ATT&CK:** T1543.003 — Create or Modify System Process: Windows Service  

---

## 1. Rule Overview

Detects creation of Windows services pointing to **non-standard directories** such as Temp or AppData.

This rule focuses on **behavior**, not just execution of `sc.exe`.

---

## 2. Data Requirements

| Requirement | Value |
|------------|------|
| SIEM | Splunk |
| Data Source | Sysmon |
| Event ID | 1 (Process Creation) |
| Index | endpoint |

---

## 3. Detection Logic

### Primary Query

```spl
index=endpoint EventCode=1
Image="*\\sc.exe"
CommandLine="*create*"
CommandLine="*binPath*"
NOT CommandLine IN (
 "*system32*",
 "*SysWOW64*",
 "*Program Files*",
 "*Program Files (x86)*"
)
| eval suspicious_path=case(
 like(CommandLine,"%Temp%"),"Temp — HIGH",
 like(CommandLine,"%AppData%"),"AppData — HIGH",
 like(CommandLine,"%Users%"),"User Dir — MEDIUM",
 1=1,"Other — Review"
)
| table _time, host, User, CommandLine, ParentImage, suspicious_path
| sort -_time
```

---

## 4. Detection Breakdown

| Field | Purpose |
|------|--------|
| Image | Detects sc.exe execution |
| CommandLine | Identifies service creation |
| binPath | Shows payload location |
| suspicious_path | Risk classification |

---

## 5. Supporting Detections

### Registry Confirmation (Event ID 13)

```spl
index=endpoint EventCode=13
TargetObject="*Services*"
```

### File Creation (Event ID 11)

```spl
index=endpoint EventCode=11
TargetFilename="*Temp*"
```

### Correlation

```spl
index=endpoint
(EventCode=11 OR EventCode=1 OR EventCode=13)
| transaction host maxspan=5m
```

---

## 6. False Positives

| Scenario | Likelihood | Action |
|---------|-----------|--------|
| Software installs | Low-Medium | Verify path |
| Admin test service | Possible | Document behavior |
| Deployment tools | Possible | Whitelist process |
| AV tools | Low | Already excluded |

---

## 7. Performance Metrics

| Metric | Value |
|-------|------|
| Detection Time | < 3 minutes |
| False Positives | Low |
| Coverage | All sc.exe persistence |

---

## 8. Analyst Checklist

1. Check binPath  
2. Validate directory  
3. Identify parent process  
4. Confirm registry entry  
5. Check payload file  
6. Determine scope  

---

## 9. Key Insight

> Service creation persistence is dangerous because it combines  
> **stealth + persistence + SYSTEM privileges**.
