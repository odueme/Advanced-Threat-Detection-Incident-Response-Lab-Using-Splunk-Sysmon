# Incident Report  
## SOC Home Lab — Simulated Threat Detection Exercise  

**Report ID:** IR-2026-003  
**Classification:** CONFIDENTIAL — INTERNAL USE ONLY  
**Date:** May 13, 2026  
**Analyst:** Odueme Uzoezi Francis 
**Severity:** HIGH  
**MITRE ATT&CK:** T1543.003 — Create or Modify System Process: Windows Service  
**Status:** RESOLVED  

---

## 1. Executive Summary

A simulated persistence attack was executed using a malicious Windows service.  
The attacker created a service (`WindowsHealthSvc`) that executes at system boot with **SYSTEM privileges**.

Sysmon detected the activity via **Event ID 1 (Process Creation)** and the alert triggered within minutes.

---

## 2. Timeline of Events

| Time | Event |
|------|------|
| 15:00 | PowerShell opened |
| 15:01 | Service created via sc.exe |
| 15:01 | Service registered |
| 15:02 | Sysmon Event ID 1 logged |
| 15:03 | Splunk alert triggered |
| 15:04 | Email alert received |
| 15:05 | Incident confirmed |

---

## 3. Attack Narrative

### What is a Windows Service?

A Windows service:
- Runs in the background  
- Starts automatically at boot  
- Runs with SYSTEM privileges  

### Attack Command

```bash
sc create WindowsHealthSvc binPath= "C:\Windows\Temp\payload.exe" start= auto
```

### Why This Works
- Persistence survives reboot  
- No user interaction required  
- High privilege execution  

---

## 4. Technical Details

| Field | Value |
|------|------|
| Event ID | 1 |
| Image | sc.exe |
| Command | create + binPath |
| Payload Path | C:\Windows\Temp\payload.exe |
| Parent | cmd.exe |
| Privilege | SYSTEM |

---

### Detection Query

```spl
index=endpoint EventCode=1
Image="*\\sc.exe"
CommandLine="*create*"
CommandLine="*binPath*"
NOT CommandLine IN ("*system32*", "*SysWOW64*", "*Program Files*")
| table _time, host, User, Image, CommandLine, ParentImage
| sort -_time
```

---

## 5. Investigation Steps

### Step 1 — Confirm Alert
```spl
index=endpoint EventCode=1 Image="*sc.exe" CommandLine="*create*"
```

### Step 2 — Check Registry
```spl
index=endpoint EventCode=13 TargetObject="*Services*"
```

### Step 3 — Check Payload
```spl
index=endpoint EventCode=11 TargetFilename="*Temp*"
```

### Step 4 — Scope
```spl
index=endpoint EventCode=1 Image="*sc.exe"
| stats count by host
```

---

## 6. Findings

| Finding | Detail |
|--------|-------|
| Attack Method | sc.exe |
| Service Name | WindowsHealthSvc |
| Payload | Temp directory |
| Privilege | SYSTEM |
| Detection Time | < 3 minutes |
| MITRE | T1543.003 |

---

## 7. Containment Actions

| Action | Status |
|-------|------|
| Alert confirmed | Complete |
| Service identified | Complete |
| Payload located | Complete |
| Incident documented | Complete |

---

## 8. Conclusion

Service-based persistence is highly effective due to:
- Automatic execution  
- High privilege  
- Stealth  

Detection at **creation time** is critical for prevention.
