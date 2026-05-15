# Lessons Learned Report  
## Post-Simulation Review — Malicious Windows Service Creation Detection  

**Report ID:** LL-2026-003  
**Reference:** IR-2026-003  
**Date:** May 13, 2026  
**Analyst:** Odueme Uzoezi Francis

---

## 1. Simulation Summary

| Area | Details |
|------|--------|
| Objective | Detect malicious service-based persistence |
| Tool Used | sc.exe (built-in Windows utility) |
| Detection | Sysmon Event ID 1 |
| Result | Successful detection within 3 minutes |

### Key Observations
- Detection pipeline worked end-to-end  
- Command line provided full context  
- Understanding services.exe behavior was key challenge  

---

## 2. Technical Lessons

### Lesson 1 — Services Are High-Risk Persistence

| Method | Requires Login | Privilege | Survives Reboot |
|-------|--------------|----------|----------------|
| Registry Run Key | Yes | User | Yes |
| Scheduled Task | Optional | User/SYSTEM | Yes |
| Windows Service | No | SYSTEM | Yes |

👉 Services provide the highest level of persistence  

---

### Lesson 2 — Command Line is Critical

- Sysmon Event ID 1 captures full command line  
- `binPath` reveals payload location  
- Without it, intent is unclear  

---

### Lesson 3 — services.exe is Normal Behavior

- sc.exe registers service  
- services.exe executes it  
- Detection must focus on **sc.exe**, not services.exe  

---

### Lesson 4 — Service Names Are Deceptive

- Attackers use realistic names (e.g., WindowsHealthSvc)  
- Detection must focus on:
  - binPath  
  - execution behavior  

---

### Lesson 5 — sc.exe is a LOLBin

- Legitimate binary used maliciously  
- Cannot be blocked  
- Must detect behavior instead  

---

## 3. Logging Insights

| Without Sysmon | With Sysmon |
|---------------|------------|
| Basic process logs | Full command line |
| Limited context | Parent process visibility |
| No binPath detail | Complete execution context |

---

## 4. SOC Workflow

1. Check binPath location  
2. Identify parent process  
3. Confirm registry entry  
4. Check payload file  
5. Determine scope  
6. Contain and escalate  

---

## 5. Key Takeaways

| Insight | Application |
|--------|------------|
| Services = strongest persistence | Treat as critical |
| Command line is key field | Ensure logging enabled |
| services.exe is expected | Avoid false alerts |
| Names are unreliable | Focus on behavior |
| LOLBins require behavior detection | Monitor usage |

---

## 6. Final Insight

> Detecting service creation at the moment of registration  
> is the most effective way to stop persistent attackers.
