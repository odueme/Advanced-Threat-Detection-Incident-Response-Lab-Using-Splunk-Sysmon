# Portfolio Case Study  
## Detecting Malicious Windows Service Creation in a SOC Environment  

**Case Study ID:** CS-2026-003  
**Technique:** T1543.003 — Windows Service Persistence  
**Tools Used:** Sysmon, Splunk, Windows Event Logs, sc.exe  
**Analyst:** Odueme Uzoezi Francis 
**Date:** May 13, 2026  

---

## 1. Scenario

An attacker gains access to a Windows endpoint and wants **persistent, high-privilege access**.

### Objective
Detect service-based persistence before execution at system boot.

---

## 2. Attack Overview

| Step | Action |
|-----|-------|
| 1 | Open command prompt as admin |
| 2 | Execute sc.exe |
| 3 | Create malicious service |
| 4 | Service configured to auto-start |

### Attack Command
```bash
sc create WindowsHealthSvc binPath= "C:\Windows\Temp\payload.exe" start= auto
```

---

## 3. Why Services Are Dangerous

| Technique | Trigger | Privilege | Visibility |
|----------|--------|----------|------------|
| Registry Run Key | User login | User | Visible |
| Scheduled Task | Event/Schedule | User/SYSTEM | Moderate |
| Windows Service | System boot | SYSTEM | Low |

👉 Services run automatically with highest privileges  

---

## 4. Detection

### Key Event

| Field | Value |
|------|------|
| Event ID | 1 |
| Process | sc.exe |
| Command | create + binPath |
| Payload Path | Temp directory |
| Parent | cmd.exe |

---

### Detection Query

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

## 5. Why This Detection Works

- Detects behavior, not service name  
- Focuses on **binPath location**  
- Identifies non-standard directories  

> Service name is attacker-controlled — path is not  

---

## 6. Results

| Capability | Result |
|-----------|--------|
| Command line visibility | Confirmed |
| Detection of malicious service | Confirmed |
| Tool-agnostic detection | Confirmed |
| Alert pipeline | Working |
| Detection time | < 3 minutes |
| False positives | Low |

---

## 7. SOC Impact

- Detects persistence before execution  
- Prevents long-term access  
- Enables fast containment  

---

## 8. Skills Demonstrated

- Sysmon configuration  
- SPL query development  
- Behavioral detection engineering  
- MITRE ATT&CK mapping  
- Service persistence analysis  

---

## 9. Improvements (Production)

| Improvement | Benefit |
|------------|--------|
| Correlate Event ID 1 + 7045 | Dual confirmation |
| Parent process scoring | Better prioritization |
| Service baseline monitoring | Detect new services |

---

## 10. Final Takeaway

Service-based persistence is one of the most powerful attacker techniques.  

Detecting it at creation time provides the best opportunity to stop attackers early.
