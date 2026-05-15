# Incident Report  
## SOC Home Lab — Simulated Threat Detection Exercise  

**Report ID:** IR-2026-004  
**Classification:** CONFIDENTIAL — INTERNAL USE ONLY  
**Date:** May 13, 2026  
**Analyst:** Odueme Uzoezi Odueme
**Severity:** HIGH  
**MITRE ATT&CK:** T1053.005 — Scheduled Task  
**Status:** RESOLVED  

---

## 1. Executive Summary

A simulated persistence attack used PowerShell to create a malicious scheduled task  
(`MicrosoftEdgeUpdateTaskCore`) designed to blend into legitimate system activity.

The task executed a payload every 5 minutes with SYSTEM privileges.

Detection was achieved via Sysmon Event ID 1 and Event ID 11 within 3 minutes.

---

## 2. Timeline of Events

| Time | Event |
|------|------|
| 13:00 | PowerShell opened (admin) |
| 13:01 | Scheduled task created |
| 13:02 | Sysmon Event ID 1 logged |
| 13:02 | Sysmon Event ID 11 logged |
| 13:03 | Splunk alert triggered |
| 13:04 | Email alert received |
| 13:05 | Incident confirmed |

---

## 3. Attack Narrative

### What is a Scheduled Task?

- Automates execution based on triggers  
- Can run as SYSTEM  
- Survives reboot  

### Attack Method

```powershell
Register-ScheduledTask -TaskName "MicrosoftEdgeUpdateTaskCore"
```

### Key Characteristics
- Runs every 5 minutes  
- Executes payload from Temp directory  
- Uses SYSTEM privileges  

---

## 4. Technical Details

| Field | Value |
|------|------|
| Event ID | 1 |
| Image | powershell.exe |
| Command | Register-ScheduledTask |
| Parent | cmd.exe |
| User | Administrator |

### File Creation (Event ID 11)

| Field | Value |
|------|------|
| Image | svchost.exe |
| TargetFilename | C:\Windows\System32\Tasks\MicrosoftEdgeUpdateTaskCore |

---

## 5. Detection Query

```spl
index=endpoint EventCode=1
Image="*\\powershell.exe"
CommandLine="*Register-ScheduledTask*"
NOT CommandLine IN ("*Microsoft*","*Windows*","*MicrosoftEdge*")
| table _time, host, User, CommandLine, ParentImage
| sort -_time
```

---

## 6. Findings

| Finding | Detail |
|--------|-------|
| Attack Method | PowerShell |
| Task Name | MicrosoftEdgeUpdateTaskCore |
| Payload Location | Temp directory |
| Trigger | Every 5 minutes |
| Privilege | SYSTEM |
| Detection Time | < 3 minutes |
| MITRE | T1053.005 |

---

## 7. Containment Actions

| Action | Status |
|-------|------|
| Alert confirmed | Complete |
| Task identified | Complete |
| Payload documented | Complete |
| Detection validated | Complete |

---

## 8. Conclusion

Scheduled task persistence is flexible and widely used by attackers.

Detection at task creation provides the best opportunity for early response.
