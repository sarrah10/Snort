# Snort Challenge 2 - Complete Write-Up

This challenge demonstrates how Snort can be used in sniffer mode to analyze live traffic and in IPS mode to actively block attacks by writing custom rules.

## Scenario 1: Brute-Force Attack (SSH)

### Step 1: Run Snort in Sniffer Mode
We start Snort in verbose sniffer mode and log packets to the current directory.
```
sudo snort -v -l .
```
we use the ```-l``` to log and the ```.``` to log it in our current directory.

Let Snort capture traffic for 10–15 seconds, then stop it using CTRL + C.
Snort generates a log file named:
```
snort.log.<number>
```

### Step 2: Read the Captured Packets

To analyze the captured traffic:
```
sudo snort -r snort.log.<number> -X
```
While reviewing packets, repeated traffic involving port 22 appeared frequently.Since port 22 is used by SSH, this suggests a brute-force attack.


### Step 3: Filter SSH Traffic

Filter packets related to port 22:
```
sudo snort -r snort.log.1672414629 -X | grep :22
```

Search for SSH strings in packet contents:
```
sudo snort -r snort.log.1672414629 -X | grep "ssh"
```

Limit output for easier inspection:
```
sudo snort -r snort.log.1672414629 -X -n 30
```

The packets show repeated SSH connection attempts - clear evidence of a brute-force attack.

### Step 4: Create an IPS Rule to Block SSH Brute-Force

Open the local rules file:
```
sudo gedit /etc/snort/rules/local.rules
```

Add the following rule:
```
drop tcp any 22 <> any any (msg:"SSH Connection attempted"; sid:100001; rev:1;)
```

Rule Explanation

- ```drop``` → Blocks the traffic (IPS mode)
- ```tcp``` → Protocol used
- ```any 22``` → Any source IP using port 22
- ```<>``` → Bidirectional rule
- ```msg``` → Alert message
- ```sid``` → Unique rule ID
- ```rev``` → Rule revision

Save and exit the editor.

### Step 5: Run Snort in IPS Mode

Now we run Snort in IPS mode to actively block the brute-force traffic.

Snort IPS mode uses DAQ with the afpacket module.
```
sudo snort -c /etc/snort/snort.conf -Q --daq afpacket -i eth0:eth1 -A full
```

Explanation:

- ```-Q``` enables inline (IPS) mode Snort 
- ```--daq``` afpacket allows packet interception
- You can also activate `-Q-- daq afpacket` mode by editing the `/etc/snort/snort.conf` file.
- ```-i eth0:eth1``` bridges traffic between interfaces ()
- ```-A full``` logs full alert details

Let Snort run for at least one minute. Once the malicious traffic is blocked successfully.

Answers

- Service under attack: SSH
- Protocol/Port used: TCP/22

---

## Scenario 2: Reverse Shell Attack

### Step 1: Run Snort in Sniffer Mode
Again, start Snort in verbose sniffer mode and log packets.
```
sudo snort -v -l .
```
Let Snort capture traffic for 10–15 seconds, then stop it using CTRL + C.
Snort generates a log file named:
```
snort.log.<number>
```

### Step 2: Read the Captured Packets

To analyze the captured traffic:
```
sudo snort -r snort.log.<number> -X
```
While analyzing the packets, port 4444 repeatedly appears in both source and destination fields. This port is commonly associated with reverse shells.

### Step 3: Filter Suspicious Traffic

Search for packets using port 4444:
```
sudo snort -r snort.log.<number> -X | grep :4444
```

Limit the number of displayed packets:
```
sudo snort -r snort.log.<number> -X -n 10
```
The packet contents clearly indicate reverse shell activity.

### Step 4: Create an IPS Rule to Block Reverse Shell

Open the local rules file:
```
sudo gedit /etc/snort/rules/local.rules
```

Add the following rule:
```
drop tcp any 4444 <> any any (msg:"Reverse Shell Detected"; sid:100001; rev:1;)
```
Explanation:
- Blocks TCP traffic on port 4444
- Works bidirectionally
- Stops reverse shell communication

### Step 5: Run Snort in IPS Mode

Now we run Snort in IPS mode to actively block the brute-force traffic.

Snort IPS mode uses DAQ with the afpacket module.
```
sudo snort -c /etc/snort/snort.conf -Q --daq afpacket -i eth0:eth1 -A full
```
Snort now blocks the reverse shell attack in real time.

Answers

- Protocol/Port used: TCP/4444
- Tool associated with this port: Metasploit
