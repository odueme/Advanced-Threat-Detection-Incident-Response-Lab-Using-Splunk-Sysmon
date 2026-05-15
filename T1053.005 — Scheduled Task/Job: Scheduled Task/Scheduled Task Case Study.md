# Portfolio Case Study  
## Detecting Scheduled Task Persistence in a Windows SOC Environment  

**Case Study ID:** CS-2026-004  
**Technique:** T1053.005 — Scheduled Task  
**Tools Used:** Sysmon, Splunk, Windows Event Logs, PowerShell  
**Analyst:** Odueme Uzoezi Francis 
**Date:** May 13, 2026  

---

## 1. Scenario

An attacker gains access to a Windows endpoint and wants **persistent execution of a payload**.

### Objective
Detect scheduled task persistence before repeated execution occurs.

---

## 2. Attack Overview

| Step | Action |
|-----|-------|
| 1 | Open PowerShell (admin) |
| 2 | Create scheduled task |
| 3 | Configure trigger (every 5 minutes) |
| 4 | Payload executes automatically |

### Attack Command

```powershell
Register-ScheduledTask -TaskName "MicrosoftEdgeUpdateTaskCore"
```

---

## 3. Why Scheduled Tasks Are Effective

| Feature | Benefit |
|--------|--------|
| Flexible triggers | Runs on schedule, login, or boot |
| High privilege | Can run as SYSTEM |
| Persistence | Survives reboot |
| Stealth | Blends into system tasks |

---

## 4. Detection

### Key Events

| Event ID | Purpose |
|---------|--------|
| 1 | PowerShell process creation |
| 11 | Task file creation |

---

### Detection Queries

#### Primary (PowerShell)

```spl
index=endpoint EventCode=1
Image="*\\powershell.exe"
CommandLine="*Register-ScheduledTask*"
NOT CommandLine IN ("*\\Windows\\*","*\\Program Files\\*")
| eval risk_level=case(
 like(CommandLine,"%Highest%") OR like(CommandLine,"%SYSTEM%"),"HIGH",
 like(CommandLine,"%Temp%") OR like(CommandLine,"%AppData%"),"HIGH",
 1=1,"MEDIUM"
)
| table _time, host, User, CommandLine, ParentImage, risk_level
| sort -_time
```

---

#### Secondary (File Creation)

```spl
index=endpoint EventCode=11
TargetFilename="*\\System32\\Tasks\\*"
NOT TargetFilename IN ("*\\Microsoft\\*","*\\Windows\\*")
| table _time, host, Image, TargetFilename
| sort -_time
```

---

## 5. Why This Detection Works

- Dual-source detection (Event ID 1 + 11)  
- Detects behavior, not task name  
- Covers PowerShell-based persistence  

> Even if one signal is missed, the second confirms the attack  

---

## 6. Results

| Capability | Result |
|-----------|--------|
| Command line visibility | Confirmed |
| File creation detection | Confirmed |
| Dual detection pipeline | Confirmed |
| Alert pipeline | Working |
| Detection time | < 3 minutes |
| False positives | Low |

---

## 7. SOC Impact

- Early detection before execution loop  
- High-confidence alerts due to dual signals  
- Reduced false positives  

---

## 8. Skills Demonstrated

- Sysmon Event ID 1 + 11 analysis  
- SPL query development  
- Detection engineering  
- MITRE ATT&CK mapping  
- Defense-in-depth design  

---

## 9. Improvements (Production)

| Improvement | Benefit |
|------------|--------|
| Correlate Event ID 1 + 11 | Higher confidence alerts |
| Add schtasks.exe rule | Broader coverage |
| Monitor execution phase | Detect active payload |

---

## 10. Final Takeaway

Scheduled task persistence is highly flexible and widely used by attackers.  

Detecting both creation and file write events provides strong, reliable detection.
