# incident-privilege-escalation-account-persistence

## Incident Title 

Multi-stage incident involving unauthorised account creation, privilege escalation, persistence and lateral movement

## Incident Verdict

Malicious

---

## Executive Summary 

The investigation identified a multi-stage attack involving unauthorised account creation and privilege escalation across multiple hosts. The attacker created two accounts ("system32" and "Guest"), escalated privileges, and established persistence by disabling password expiration.

The compromised account was used to access additional systems, confirming lateral movement. Multiple external IP addresses were observed, suggesting the use of VPN or proxy infrastructure.

The activity demonstrates a highly likely compromise of the Administrator account with persistence and lateral movement. 

---

## Findings

### Time: 

- First Activity - 16 Mar 2026 05:22:29
- Last Activity - 16 Mar 2026 18:40:07
- Alert Generated - 16 Mar 2026 05:25:52

### Incident:

- Unauthorised account creation followed by privilege escalation and persistence activity

### Affected Accounts: 

- Administrator (initiating account)
- system32 (malicious account created)
- Guest (account modified and elevated)

### Affected Hosts:

- mts-contractorpc1
- mts-dc.mts.local

---

## Incident Overview

### WHO: 

**Accounts Involved:**

- system32
- Guest

**WHAT:**

Suspicious activity identified involving: 

- Unauthorised account creation
- Privilege escalation via group modification
- Persistence via account configuration

**Key Actions Observed:**

- net user system32 ******** /add
- net user Guest ******** /add
- net localgroup Administrators system 32 /add
- net localgroup Administrators Guest /add
- WMIC UserAccount WHERE Name='system32' SET PasswordExpires=FALSE
- WMIC UserAccount WHERE Name='Guest' SET PasswordExpires=FALSE

**WHEN:**

- 16 Mar 2026 05:25:52 - 16 Mar 2026 18:40:07

**WHERE:**

**Hosts:**

- mts-contractorpc1
- mts-dc.mts.local

**WHY:**

Likely objective of activity:

- Establish persistent access through creation of local accounts
- Escalate privileges to administrative level for full system control
- Evade detection using deceptive account naming ("system32") to mimic legitimate system components
- Maintain long-term access by disabling password expiration

**HOW:**

**Execution Method:**

- Remote Desktop Protocol (RDP) session observed

**Account Activity:**

- Creation of two local accounts (system32, Guest)
- Modification of account properties

**Privilege Escalation Mechanism:**

- Accounts added to the Administrators group using net local group

**Process Characteristics:**

- Use of native Windows binaries (LOLBins):
  - net.exe
  - wmic.exe

---

## Technical Analysis

### Account Activity Analysis

- Two accounts were created and modified within a short timeframe
- Activity was performed under the Administrator account
- Account names indicate attempts to blend in with legitimate system components
- Behaviour deviates from normal administrative activity patterns

### Privilege Escalation Analysis

- Both accounts were added to the Administrators group
- Privilege escalation occurred immediately after account creation
- Indicates intentional abuse of administrative privileges

### Process Execution Analysis 

- Parent process: cmd.exe
- Child processes:
  - net.exe
  - wmic.exe
- Analysis:
  - The use of native Windows tools (net.exe, wmic.exe) indicates living-off-the-land techniques, allowing the attacker to evade traditional signature-based detection
 
### Network Activity

- External IPs observed:
  - 45.77.241.31
  - 45.77.241.32
  - 45.77.241.41
  - 45.77.126.234
  - 45.76.97.142
  - 45.77.129.243
- Internal IP:
  - 10.42.185.22
- Analysis:
  - No known malicious reputation associated with IPs
  - Multiple geographically diverse IPs observed within short timeframe
  - Behaviour suggests the use of VPN or proxy infrastructure
  - RDP sessions associated with these IPs indicate attacker-controlled access
 
### Persistence Mechanisms

- Account-based persistence identified
- Password expiration disabled for created accounts
- Ensures continued access even if credentials are not rotated

### File Activity 

- No file artefacts observed
- Activity consistent with fileless command-line driven attack

### Lateral Movement

- Evidence of lateral movement observed
- system32 account logged into mts-dc.mts.local
- Indicates attacker reused compromised account across hosts
- Suggests expansion beyond initial endpoint
- Activity suggests attacker established control but did not fully propagate

### Scope Assessment 

- Affected devices:
  - mts-contractorpc1
  - mts-dc.mts.local
- Affected users:
  - system32
  - Guest
- Analysis:
  - Multiple hosts involved
  - Single administrator account compromised
  - Multiple accounts created
- Analysis
  - Activity observed across two hosts (mts-contractorpc1 and mts-dc.mts.local)
  - system32 account used on multiple systems
  - Multiple accounts created and modified
  - Confirms lateral movement beyond the initially compromised endpoint
 
--- 

## MITRE ATT&CK Mapping

- T1136 - Create Account
- T1098 - Account Manipulation
- T1078 - Valid Accounts
- T1021.001 - Remote Desktop Protocol

---

## Verdict 

- Malicious

### Justification 

- Unauthorised account creation observed
- Privilege escalation via administrative group assignment
- Persistence established through account modification
- Use of deceptive account naming ("system32")
- Guest account not typically characteristic of account with administrative permissions
- RDP access from multiple geographically diverse IP addresses
- Behaviour is consistent with attacker tradecraft

### Recommendations

- Reset credentials for Administrator account
- Enforce MFA for privileged accounts
- Remove unauthorised accounts (system32, modified Guest account)
- Block suspicious IP addresses
- Review logs for additional persistence mechanisms
- Implement monitoring for account creation and privilege escalation events

---

## Supporting Evidence

The following evidence is presented in chronological order to reflect the investigation workflow, from initial alert triage through to scope validation. 

### Alert Validation 

<img width="1917" height="993" alt="Screenshot 2026-03-21 at 20 29 22 (1)" src="https://github.com/user-attachments/assets/059b708a-eb15-46df-a9b1-72849ac19a3a" />

**Figure 1:** Shows incident ID 1598, classified as a multi-stage incident involving privilege escalation on one endpoint. The incident is marked with medium severity and active status, providing the starting point for triage. 

<img width="328" height="182" alt="Screenshot 2026-03-21 at 20 28 20 (1)" src="https://github.com/user-attachments/assets/3fc0286e-4925-48d8-a739-7f2a6d574709" />

**Figure 2:** Shows the incident timing, including first activity, last activity, and incident creation time. This establishes the activity window used throughout the investigation. 

<img width="1417" height="150" alt="Screenshot 2026-03-21 at 20 34 14 (1)" src="https://github.com/user-attachments/assets/46352bbf-ea12-430c-9e9f-9b2f0a822d86" />

**Figure 3a:** Shows the primary affected device as mts-contractorpc1, initially indicating a single-endpoint investigation target. 

<img width="1419" height="181" alt="Screenshot 2026-03-21 at 20 35 57 (1)" src="https://github.com/user-attachments/assets/ca0c7027-df81-48ef-bf9f-51d41e0110c8" />

**Figure 3b:** Shows the user accounts associated with the incident, including administrator and system32, which were used as initial pivots for investigation.

<img width="301" height="152" alt="Screenshot 2026-03-21 at 20 31 43 (1)" src="https://github.com/user-attachments/assets/de286164-5d9d-4315-a5d7-d01d6d408370" />

**Figure 4:** Shows the product explanation that a new user was created and that such behaviour may indicate attacker attempts to maintain access.

### Investigate Account Activity

<img width="1067" height="112" alt="Screenshot 2026-03-21 at 20 47 26 (1)" src="https://github.com/user-attachments/assets/0f6bc961-7d1e-4890-911c-6a7493509758" />

**Figure 5:** Shows the creation of the system32 account, supporting the finding of unauthorised account creation.

<img width="1062" height="134" alt="Screenshot 2026-03-21 at 20 58 49" src="https://github.com/user-attachments/assets/0d4f4f00-f98c-4608-aa4f-612a237c23e2" />

**Figure 6:** Shows that a user account was added to the Administrators group, supporting the finding of privilege escalation. 

### Review Process Execution

<img width="1241" height="289" alt="Screenshot 2026-03-21 at 21 21 11 (1)" src="https://github.com/user-attachments/assets/ea3fe3a0-68c7-4616-9ddf-c6edf80bdcc2" />

**Figure 7:** Shows command-line activity involving Windows utilities used to create or modify accounts. This supports the conclusion that the attacker used built-in administrative tools for execution. 

### Investigate Network Activity 

<img width="1920" height="1080" alt="Screenshot 2026-03-21 at 21 41 59 (1)" src="https://github.com/user-attachments/assets/15cb6edc-f325-409b-a7b2-e19512025f1a" />

**Figure 8:** Shows multiple IP addresses associated with the incident. This supports the remote access component of the investigation and provides indicators of enrichment.

<img width="1313" height="177" alt="Screenshot 2026-03-21 at 21 48 34 (1)" src="https://github.com/user-attachments/assets/81734695-3355-4504-b4f7-43214d01c970" />

**Figure 9a:** Shows no security vendor detections at the time of review. Despite low reputation-based concern, the address remains relevant due to its presence in the incident timeline.

<img width="1301" height="172" alt="Screenshot 2026-03-21 at 21 50 28 (1)" src="https://github.com/user-attachments/assets/37c7cf14-4ff0-47fb-aae0-dcaca4fd2e1e" />

**Figure 9b:** Shows no security vendor detections at the time of review. This demonstrates that lack of public detections does not rule out malicious use.

<img width="1296" height="170" alt="Screenshot 2026-03-21 at 21 52 12 (1)" src="https://github.com/user-attachments/assets/6977392f-f9b9-404e-b449-fe563416b1a9" />

**Figure 9c:** Shows no security vendor detections at the time of review and supports the assessment that the incident involved suspicious but not necessarily previously known infrastructure.

<img width="1299" height="172" alt="Screenshot 2026-03-21 at 21 52 55 (1)" src="https://github.com/user-attachments/assets/940b28d1-9de9-47ea-8c65-806bb0fb82f0" />

**Figure 9d:** Shows no security vendor detections at the time of review. This IP remains significant because it appears in incident-related telemetry. 

<img width="1301" height="170" alt="Screenshot 2026-03-21 at 21 54 01 (1)" src="https://github.com/user-attachments/assets/0f9a4ef5-d23d-45af-bc5b-e5c1d7f164d1" />

**Figure 9e:** Shows no security vendor detections at the time of review and contributes to the pattern of geographically distributed external connectivity.

<img width="1301" height="176" alt="Screenshot 2026-03-21 at 21 55 08 (1)" src="https://github.com/user-attachments/assets/9a0c44f7-1012-4b5f-a3df-5d735e214732" />

**Figure 9f:** Shows no security vendor detections at the time of review and supports the assessment of suspicious remote-access infrastructure.

### Check for Lateral Movement

<img width="1695" height="902" alt="Screenshot 2026-03-21 at 22 08 06 (1)" src="https://github.com/user-attachments/assets/dad09b90-f851-41c2-9e1d-0df155e68497" />

**Figure 10:**  Shows remote desktop session evidence tied to the compromised host and suspicious account activity. This supports the conclusion that the system was accessed interactively and helps explain how the attacker operated post compromise. 

### Scope The Incident

<img width="1233" height="255" alt="Screenshot 2026-03-22 at 18 49 39 (1)" src="https://github.com/user-attachments/assets/69e92bfa-7a5f-413a-9435-8037d448e271" />

**Figure 11:** Shows logon activity for system32 on both mts-contractorpc1 and mts-dc.mts.local. This is key evidence confirming lateral movement.

<img width="1233" height="231" alt="Screenshot 2026-03-22 at 19 03 17 (1)" src="https://github.com/user-attachments/assets/749373c0-31b0-4fde-9400-5fd06e63de33" />

**Figure 12:** Shows command-line patterns associated with account creation and administrative group modification. This supports the findings of account abuse and privilege escalation.

<img width="1235" height="291" alt="Screenshot 2026-03-22 at 19 05 26 (2)" src="https://github.com/user-attachments/assets/fdcd2743-7abb-4bf7-8f99-313e76ae218e" />

**Figure 13:** Shows command setting PasswordExpires=FALSE for user accounts, supporting the persistence finding. 


