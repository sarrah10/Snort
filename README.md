# Snort

This repository documents my hands-on practice with **Snort IDS/IPS**, where I analyzed network traffic, wrote custom detection rules, and blocked simulated attacks in real time.

The labs focus on practical intrusion detection, packet analysis, and understanding how network-based threats appear at the traffic level.

---

## Repository Contents

### 1️⃣ Snort Interaction and Operation Modes  
**File:** [Snort - First Interaction & Operation Modes](./snort-interaction%20and%20operation%20modes.md)

This guide explains how Snort operates in different modes and how to interact with it effectively.

Covered topics:
- Sniffer mode  
- Packet logger mode  
- Network Intrusion Detection System (NIDS) mode  
- Intrusion Prevention System (IPS) mode  
- Common command-line options and logging behavior
  
---
  
### 2️⃣ Snort Challenge 1  
**File:** [Snort Challenge 1](./snort%20challenge-1.md)

This challenge focuses on **traffic analysis and rule creation** using recorded PCAP files.

Covered topics:
- Detecting HTTP and FTP traffic  
- Identifying login attempts and suspicious activity  
- Writing rules to detect file signatures (PNG, GIF)  
- Detecting BitTorrent metafiles in traffic  
- Troubleshooting Snort rule syntax and logic errors  
- Analyzing exploit traffic such as **MS17-010** and **Log4Shell**  

---

### 3️⃣ Snort Challenge 2  
**File:** [Snort Challenge 2](./snort%20challenge-2.md)

This challenge demonstrates using Snort in both **sniffer mode** and **IPS mode**.

Covered topics:
- Capturing live traffic using Snort sniffer mode  
- Identifying a **brute-force SSH attack**  
- Writing IPS rules to block malicious traffic  
- Detecting and blocking a **reverse shell attack**  
- Running Snort in inline IPS mode using DAQ  

---

## Tools Used

- **Snort**
- PCAP files
- Linux command line utilities (grep, strings, nano, etc.)

---

This repository represents practical blue-team learning and hands-on experience with network intrusion detection and prevention.
