INCIDENT REPORT

SOC Home Lab — Simulated Threat Detection Exercise

Report ID: IR-2026-001 Classification: CONFIDENTIAL — INTERNAL USE ONLY Date: May 5, 2026 Analyst: Odueme Uzoezi Francis Severity: HIGH Status: RESOLVED

EXECUTIVE SUMMARY

A simulated persistence attack was executed against a controlled Windows 10 endpoint within a home lab environment. The threat actor (simulated) planted a malicious registry Run key entry designed to execute a payload ( malware.exe ) on every user login. The attack was successfully detected by Sysmon (Event ID 13) and confirmed via Splunk within approximately 5 minutes of execution. An automated email alert was triggered, confirming the end-to-end detection pipeline is functional.

INCIDENT TIMELINE

ATTACK DESCRIPTION

3.1 Attack Vector

The attacker gained code execution on a Windows 10 endpoint (simulated) and used PowerShell to write a malicious entry into the Windows Registry Run key — a location Windows reads automatically at every user login to launch programs.

3.2 Command Executed

New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `

-Name "WindowsUpdate" `     -Value "C:\Users\Public\malware.exe" `     -PropertyType String `

-Force

3.3 Attacker Objective

By writing to the Run key, the attacker ensures that malware.exe is launched automatically every time the user logs into Windows — even if the endpoint is rebooted or antivirus removes the payload from disk, the registry entry remains until manually cleaned, causing re-infection on next login.

3.4 Why This Technique Is Dangerous

DETECTION

4.1 Detection Source

4.2 Key Log Fields Captured

4.3 Detection Query (SPL)

index=endpoint EventCode=13 "powershell.exe" "CurrentVersion\\Run" | table _time, host, User, Image, TargetObject, Details

| sort -_time

4.4 Alert Configuration

MITRE ATT&CK MAPPING

IMPACT ASSESSMENT

CONTAINMENT & REMEDIATION

Immediate Actions Taken

Identified the malicious registry key via Splunk investigation

Removed the registry entry:

Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -

Confirmed removal by re-querying Splunk for subsequent Event ID 13 activity

Recommended Production Actions

Isolate the affected endpoint immediately upon alert

EVIDENCE

ANALYST NOTES

This simulation confirmed that behavioral detection (catching the action of writing to a Run key) is more reliable than signature-based detection (trying to identify the specific malware file). The detection fired regardless of the filename or payload — it detected the attacker behavior, not the specific tool, which makes it significantly harder to evade.

Report prepared by: Odueme Uzoezi Francis | SOC Lab Documentation For portfolio and interview demonstration purposes