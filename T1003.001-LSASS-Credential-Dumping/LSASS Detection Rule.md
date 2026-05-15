# Detection Rule Documentation  
## LSASS Memory Access — Credential Dumping Detection  

**Rule ID:** DET-2026-002  
**Rule Name:** LSASS Process Memory Access by Non-System Process  
**Date Created:** May 13, 2026  
**Author:** Odueme Uzoezi Francis  
**Severity:** CRITICAL  
**Status:** ACTIVE  
**MITRE ATT&CK:** T1003.001 — OS Credential Dumping: LSASS Memory  

---

## 1. Rule Overview

Detects unauthorized access to LSASS memory by non-whitelisted processes.  
Any process requesting high-privilege access to `lsass.exe` is treated as suspicious.

---

## 2. Data Requirements

| Requirement | Value |
|------------|------|
| SIEM | Splunk |
| Data Source | Sysmon |
| Event ID | 10 (ProcessAccess) |
| Index | endpoint |

---

## 3. Detection Logic

### Primary Query
```spl
index=endpoint EventCode=10
TargetImage="C:\\Windows\\System32\\lsass.exe"
NOT SourceImage IN (
 "C:\\Windows\\System32\\svchost.exe",
 "C:\\Windows\\System32\\wininit.exe",
 "C:\\Windows\\System32\\csrss.exe",
 "C:\\Windows\\System32\\lsass.exe",
 "C:\\Windows\\System32\\services.exe",
 "C:\\Windows\\System32\\MsMpEng.exe"
)
| eval risk_level=case(
 GrantedAccess="0x1fffff","CRITICAL",
 GrantedAccess="0x1010","HIGH",
 GrantedAccess="0x143a","HIGH",
 1=1,"MEDIUM"
)
| table _time, host, SourceImage, TargetImage, GrantedAccess, risk_level
| sort -_time
```

---

## 4. Key Fields

| Field | Description |
|------|------------|
| SourceImage | Process accessing LSASS |
| TargetImage | Always lsass.exe |
| GrantedAccess | Permission level requested |
| risk_level | Derived severity |

---

## 5. GrantedAccess Reference

| Value | Meaning | Risk |
|------|--------|------|
| 0x1fffff | Full memory access | CRITICAL |
| 0x1010 | Read VM + Query | HIGH |
| 0x143a | Partial read | HIGH |
| 0x0410 | Query only | MEDIUM |

---

## 6. False Positive Guidance

| Scenario | Likelihood | Action |
|---------|-----------|--------|
| Windows Defender | Low | Already excluded |
| Third-party AV | Possible | Add to whitelist |
| Crash dumps | Low | Add WerFault.exe |
| Admin tools | Possible | Validate usage |

---

## 7. Performance Metrics

| Metric | Value |
|-------|------|
| Detection Time | < 3 minutes |
| False Positives | Low |
| Coverage | All LSASS access tools |

---

## 8. Analyst Checklist

1. Identify SourceImage  
2. Check GrantedAccess  
3. Look for `.dmp` file  
4. Check parent process  
5. Determine scope  
6. Isolate if malicious  

---

## 9. Key Insight

> This detection is behavioral it detects LSASS access, not specific tools.
