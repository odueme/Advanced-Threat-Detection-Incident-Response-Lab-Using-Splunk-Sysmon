# Incident Report  
## SOC Home Lab — Simulated Threat Detection Exercise  

**Report ID:** IR-2026-002  
**Classification:** CONFIDENTIAL — INTERNAL USE ONLY  
**Date:** May 13, 2026  
**Analyst:** Odueme Uzoezi Francis
**Severity:** CRITICAL  
**MITRE ATT&CK:** T1003.001 — OS Credential Dumping: LSASS Memory  
**Status:** RESOLVED  

---

## 1. Executive Summary

A simulated credential theft attack was executed against a controlled Windows 10 endpoint. The attacker used Task Manager to access LSASS memory and dump credentials to disk.

Sysmon detected the attack via **Event ID 10 (ProcessAccess)**. The Splunk alert triggered within minutes, confirming detection capability.

---

## 2. Timeline of Events

| Time | Event |
|------|------|
| 14:00 | Task Manager opened |
| 14:01 | LSASS dump initiated |
| 14:01 | Dump file created |
| 14:02 | Sysmon Event ID 10 logged |
| 14:03 | Splunk alert triggered |
| 14:04 | Email alert received |
| 14:05 | Incident confirmed |

---

## 3. Attack Narrative

### What is LSASS?

LSASS stores authentication credentials such as:
- NTLM hashes  
- Kerberos tickets  
- Plaintext passwords  

### Attack Method

1. Open Task Manager  
2. Navigate to Details tab  
3. Right-click lsass.exe  
4. Select Create dump file  

Output file:
C:\Users\[User]\AppData\Local\Temp\lsass.DMP

---

## 4. Technical Details

| Field | Value |
|------|------|
| Event ID | 10 |
| SourceImage | taskmgr.exe |
| TargetImage | lsass.exe |
| GrantedAccess | 0x1fffff |

### Detection Query

```spl
index=endpoint EventCode=10
TargetImage="C:\\Windows\\System32\\lsass.exe"
NOT SourceImage IN ("svchost.exe","wininit.exe","csrss.exe")
| table _time, host, SourceImage, TargetImage, GrantedAccess
```

---

## 5. Investigation Steps

### Confirm Alert
```spl
index=endpoint EventCode=10 TargetImage="*lsass*"
| table _time, host, SourceImage, GrantedAccess
```

### Check Dump File
```spl
index=endpoint EventCode=11 TargetFilename="*.dmp"
```

---

## 6. Findings

| Finding | Detail |
|--------|-------|
| Attack Method | Task Manager |
| Target | lsass.exe |
| Access | 0x1fffff |
| Dump File | lsass.DMP |
| Detection Time | < 3 minutes |

---

## 7. Conclusion

Detection successfully identified LSASS credential dumping using behavioral analysis.
