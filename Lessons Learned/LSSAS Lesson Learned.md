# Lessons Learned Report  
## Post-Simulation Review — LSASS Credential Dumping Detection  

**Report ID:** LL-2026-002  
**Reference:** IR-2026-002  
**Date:** May 13, 2026  
**Analyst:** Olayinka Oyetade  

---

## 1. Simulation Summary

| Area | Details |
|------|--------|
| Objective | Detect LSASS credential dumping behavior |
| Tool Used | Task Manager (no external malware) |
| Detection | Sysmon Event ID 10 |
| Result | Successful detection within 3 minutes |

### Key Observations
- Detection worked end-to-end  
- GrantedAccess value provided strong signal  
- Whitelisting was the main challenge  

---

## 2. Technical Lessons

### Lesson 1 — LSASS is a Critical Target
- LSASS stores credentials (NTLM, Kerberos)
- Compromise leads to lateral movement
- Detection is a high-priority SOC capability  

---

### Lesson 2 — GrantedAccess is Key

| Value | Meaning | Risk |
|------|--------|------|
| 0x1fffff | Full access | CRITICAL |
| 0x1010 | Read VM + Query | HIGH |
| 0x143a | Partial memory read | HIGH |
| 0x0400 | Query only | LOW |

👉 Any high-value access from unknown process = investigate immediately  

---

### Lesson 3 — Whitelisting is Essential

| Process | Reason |
|--------|-------|
| svchost.exe | Normal Windows service activity |
| wininit.exe | System initialization |
| csrss.exe | Windows subsystem |
| lsass.exe | Self-access |

> A rule without a whitelist = alert fatigue  

---

### Lesson 4 — Behavior > Tool Detection
- Task Manager and Mimikatz produce same behavior
- Detection must focus on LSASS access, not tool name  

---

### Lesson 5 — Sysmon is Required
- Default Windows logs do NOT capture LSASS access  
- Sysmon Event ID 10 provides visibility  

---

## 3. Detection Engineering Lessons

### Why This Rule Works
- Detects behavior, not signatures  
- Catches all LSASS dumping tools  

### Improvements

| Enhancement | Benefit |
|------------|--------|
| Parent process analysis | Detect suspicious spawn chains |
| EventCode 10 + 11 correlation | Confirm dump activity |
| Risk scoring | Faster triage |

---

## 4. SOC Workflow (Real Scenario)

1. Identify SourceImage  
2. Check GrantedAccess  
3. Look for dump file (.dmp)  
4. Check scope (single vs multiple hosts)  
5. Isolate host if malicious  
6. Escalate if widespread  

---

## 5. Key Takeaways

| Insight | Application |
|--------|------------|
| LSASS is high-value target | Treat alerts as critical |
| 0x1fffff = malicious | Immediate escalation |
| Whitelisting is essential | Maintain exclusions |
| Behavior-based detection | Stronger than signatures |
| Sysmon required | Enables visibility |

---

## 6. Final Insight

> Strong detection is built on understanding behavior, not tools.  
> LSASS access is one of the most critical signals in endpoint security.
