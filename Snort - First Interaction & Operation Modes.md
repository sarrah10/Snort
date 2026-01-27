# 🐷 Snort – First Interaction & Operation Modes

This lab introduces **Snort**, an open-source Network Intrusion Detection/Prevention System (IDS/IPS). We explore its installation, configuration validation, and different operation modes including **Sniffer**, **Logger**, **IDS/IPS**, and **PCAP Investigation**.

---

## ✅ Verifying Snort Installation

To confirm Snort is installed and check its version:

```bash
snort -V
```

This displays:
- Snort version  
- Build info  
- Libpcap, PCRE, and ZLIB versions  

---

## 🛠️ Testing Snort Configuration

Before running Snort, always validate the configuration file:

```bash
sudo snort -c /etc/snort/snort.conf -T
```

**Parameters used:**

| Parameter | Description |
|----------|-------------|
| `-c` | Specifies configuration file |
| `-T` | Tests configuration and exits |

If successful, you’ll see:

```
Snort successfully validated the configuration!
```

---

# 🕵️ Operation Mode 1: Sniffer Mode

Snort can sniff live traffic like `tcpdump`.

### Common Sniffer Flags

| Flag | Description |
|------|-------------|
| `-v` | Verbose output |
| `-d` | Show payload data |
| `-e` | Show link-layer headers |
| `-X` | Full packet dump in HEX |
| `-i` | Specify interface |

### Examples

```bash
sudo snort -v
sudo snort -v -i eth0
sudo snort -d
sudo snort -de
sudo snort -X
```

> Snort needs **live traffic**, so use the provided traffic generator script.

---

# 📝 Operation Mode 2: Packet Logger Mode

Snort can log captured packets to files.

### Logger Parameters

| Parameter | Description |
|-----------|-------------|
| `-l` | Log directory |
| `-K ASCII` | Log in ASCII format |
| `-r` | Read from log file |
| `-n` | Process limited number of packets |

### Logging Traffic

```bash
sudo snort -dev -l .
```

Logs will appear as:

```bash
ls
snort.log.XXXXXXXX
```

### ASCII Logging

```bash
sudo snort -dev -K ASCII -l .
```

### Reading Logs

```bash
sudo snort -r snort.log.xxxxx -X
sudo snort -r snort.log.xxxxx icmp
sudo snort -r snort.log.xxxxx tcp
sudo snort -r snort.log.xxxxx 'udp and port 53'
sudo snort -dvr snort.log.xxxxx -n 10
```

---

## 🔐 Logfile Ownership Issue

Since Snort runs with `sudo`, logs are owned by **root**.

### Option 1: Use sudo
```bash
sudo cat snort.log.xxxxx
```

### Option 2: Change ownership
```bash
sudo chown ubuntu:ubuntu snort.log.xxxxx
```

---

# 🚨 Operation Mode 3: IDS/IPS Mode

Snort detects threats using **rules**.

### Running IDS Mode

```bash
sudo snort -c /etc/snort/snort.conf
```

### Important IDS Parameters

| Parameter | Description |
|-----------|-------------|
| `-N` | Disable logging |
| `-D` | Run in background |
| `-A` | Alert mode |
| `-T` | Test configuration |

### Background Mode

```bash
sudo snort -c /etc/snort/snort.conf -D
ps -ef | grep snort
sudo kill -9 <PID>
```

---

## 📢 Alert Modes

| Mode | Description |
|------|-------------|
| console | Alerts printed to terminal |
| cmg | Headers + payload (hex & text) |
| fast | Fast alert format (log only) |
| full | Detailed alerts (log only) |
| none | No alerts |

### Examples

```bash
sudo snort -c /etc/snort/snort.conf -A console
sudo snort -c /etc/snort/snort.conf -A cmg
sudo snort -c /etc/snort/snort.conf -A fast
sudo snort -c /etc/snort/snort.conf -A full
sudo snort -c /etc/snort/snort.conf -A none
```

---

# 📂 Operation Mode 4: PCAP Investigation

Snort can analyze `.pcap` files.

### Reading a Single PCAP

```bash
snort -r icmp-test.pcap
sudo snort -c /etc/snort/snort.conf -q -r icmp-test.pcap -A console -n 10
```

### Multiple PCAPs

```bash
sudo snort -c /etc/snort/snort.conf -q --pcap-list="icmp-test.pcap http2.pcap" -A console
sudo snort -c /etc/snort/snort.conf -q --pcap-list="icmp-test.pcap http2.pcap" -A console --pcap-show
```

---

# 🧩 Snort Rule Structure

Basic rule format:

```
action protocol src_ip src_port direction dst_ip dst_port (options)
```

### Example Rule

```snort
alert icmp any any <> any any (msg:"ICMP Packet Found"; sid:1000001; rev:1;)
```

---

## 🔹 Rule Components

### Actions
| Action | Meaning |
|--------|---------|
| alert | Alert + log |
| log | Log only |
| drop | Block + log |
| reject | Block + terminate session |

### Protocols
Snort2 supports: `IP`, `TCP`, `UDP`, `ICMP`

---

## 🌐 IP & Port Filtering Examples

```snort
alert icmp 192.168.1.0/24 any <> any any (msg:"ICMP Found"; sid:1000002; rev:1;)
alert tcp any any <> any 21 (msg:"FTP Traffic"; sid:1000003; rev:1;)
alert tcp any any <> any !21 (msg:"Non-FTP Traffic"; sid:1000004; rev:1;)
alert tcp any any <> any 1:1024 (msg:"System Ports"; sid:1000005; rev:1;)
```

---

## 🔍 Payload Detection Options

```snort
content:"GET";
content:"|47 45 54|";
nocase;
fast_pattern;
```

Example:

```snort
alert tcp any any <> any 80 (msg:"HTTP GET Found"; content:"GET"; nocase; sid:1000006; rev:1;)
```

---

## 🧠 Non-Payload Options

```snort
flags:S;
dsize:>100;
sameip;
id:123456;
```

---

# ⚙️ Important Files

| File | Purpose |
|------|---------|
| `/etc/snort/snort.conf` | Main configuration file |
| `/etc/snort/rules/local.rules` | Custom user rules |

---

# 🧠 Snort Processing Flow

1. **Packet Decoder** – Captures packets  
2. **Preprocessors** – Normalize traffic  
3. **Detection Engine** – Matches rules  
4. **Logging & Alerting** – Generates logs/alerts  
5. **Output Plugins** – Sends output to files, DB, etc.

---

## 🎯 Key Takeaways

✔ Snort can sniff, log, detect, and prevent attacks  
✔ Logs require root access  
✔ IDS mode depends on rules  
✔ PCAP mode is powerful for offline analysis  
✔ Proper rule writing is crucial for detection accuracy  
