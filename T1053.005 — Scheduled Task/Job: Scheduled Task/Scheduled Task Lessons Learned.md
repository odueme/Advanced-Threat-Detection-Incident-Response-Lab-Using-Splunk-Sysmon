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
| Tool Used | sc.exe (Windows Service Control) |
| Detection | Sysmon Event ID 1 |
| Result | Successful detection within 3 minutes |

### Key Observations
- Full command line provided complete context  
- Detection pipeline worked end-to-end  
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
- binPath reveals payload location  
- Without command line, intent is unclear  

---

### Lesson 3 — services.exe is Normal

- sc.exe registers the service  
- services.exe executes it  
- Detection should focus on sc.exe  

---

### Lesson 4 — Service Names Are Misleading

- Names are attacker-controlled  
- Detection must focus on:
  - binPath  
  - behavior  

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
3. Confirm registry/service entry  
4. Check payload file  
5. Determine scope  
6. Contain and escalate  

---

## 5. Key Takeaways

| Insight | Application |
|--------|------------|
| Services are powerful persistence | Treat as critical |
| Command line is key | Ensure logging enabled |
| services.exe is normal | Avoid false alerts |
| Names are unreliable | Focus on behavior |
| LOLBins require behavior detection | Monitor usage |

---

## 6. Final Insight

> Service creation detection is most effective at the moment of registration  
> before persistence is established.
