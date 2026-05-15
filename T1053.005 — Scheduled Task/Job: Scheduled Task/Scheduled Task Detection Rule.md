# Detection Rule Documentation  
## Malicious Scheduled Task Creation — Persistence Detection  

**Rule ID:** DET-2026-004  
**Rule Name:** Suspicious Scheduled Task Creation via PowerShell  
**Date Created:** May 13, 2026  
**Author:** Olayinka Oyetade  
**Severity:** HIGH  
**Status:** ACTIVE  
**MITRE ATT&CK:** T1053.005 — Scheduled Task  

---

## 1. Rule Overview

Detects creation of scheduled tasks using PowerShell (`Register-ScheduledTask`) with  
suspicious payload paths or elevated privileges.

Uses:
- Event ID 1 (Process Creation)
- Event ID 11 (Task file creation)

---

## 2. Data Requirements

| Requirement | Value |
|------------|------|
| SIEM | Splunk |
| Data Source | Sysmon |
| Event ID | 1 + 11 |
| Index | endpoint |

---

## 3. Detection Logic

### Primary Rule (PowerShell)

```spl
index=endpoint EventCode=1
Image="*\\powershell.exe"
CommandLine="*Register-ScheduledTask*"
NOT CommandLine IN (
 "*\\Windows\\*",
 "*\\Program Files\\*",
 "*\\Program Files (x86)\\*"
)
| eval risk_level=case(
 like(CommandLine,"%Highest%") OR like(CommandLine,"%SYSTEM%"),"HIGH — Elevated privilege",
 like(CommandLine,"%Temp%") OR like(CommandLine,"%AppData%"),"HIGH — Suspicious path",
 1=1,"MEDIUM — Review"
)
| table _time, host, User, CommandLine, ParentImage, risk_level
| sort -_time
```

---

### Secondary Rule (Task File Creation)

```spl
index=endpoint EventCode=11
TargetFilename="*\\System32\\Tasks\\*"
NOT TargetFilename IN (
 "*\\Microsoft\\*",
 "*\\Windows\\*"
)
| table _time, host, Image, TargetFilename
| sort -_time
```

---

## 4. Companion Rule (schtasks.exe)

```spl
index=endpoint EventCode=1
Image="*\\schtasks.exe"
CommandLine="*/create*"
NOT CommandLine IN (
 "*system32*",
 "*Program Files*"
)
| table _time, host, User, CommandLine, ParentImage
| sort -_time
```

---

## 5. Detection Breakdown

| Field | Purpose |
|------|--------|
| Image | Identifies PowerShell execution |
| CommandLine | Shows task creation |
| risk_level | Adds severity context |
| TargetFilename | Confirms task file creation |

---

## 6. False Positives

| Scenario | Likelihood | Action |
|---------|-----------|--------|
| Software installs | Medium | Verify path |
| IT admin tasks | Possible | Document behavior |
| Deployment tools | Possible | Whitelist after review |
| Security tools | Low | Already excluded |

---

## 7. Threat Context

| Threat Actor | Usage |
|-------------|------|
| Emotet | Task persistence |
| TrickBot | Module reloading |
| Cobalt Strike | Post-exploitation |
| APT29 | Long-term persistence |
| Ryuk | Pre-execution staging |
| Lazarus | Campaign persistence |

---

## 8. Performance Metrics

| Metric | Value |
|-------|------|
| Detection Time | < 3 minutes |
| False Positives | Low |
| Coverage | PowerShell + schtasks |

---

## 9. Analyst Checklist

1. Check CommandLine  
2. Validate payload path  
3. Check privilege level  
4. Confirm task file (Event ID 11)  
5. Check parent process  
6. Scope across hosts  
7. Contain if malicious  

---

## 10. Key Insight

> Scheduled task detection must focus on behavior  
> — not task names — to remain effective.
