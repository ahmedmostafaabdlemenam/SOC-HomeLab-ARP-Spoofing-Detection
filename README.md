# ARP Spoofing Detection Lab

## Overview

This project demonstrates the detection and investigation of an ARP Spoofing (ARP Cache Poisoning) attack using Splunk within a SOC Home Lab environment.

The objective was to simulate realistic network traffic, identify abnormal ARP behavior, investigate suspicious activity, and develop a detection rule capable of identifying potential Man-in-the-Middle (MITM) attacks.

---

## Project Objectives

* Analyze ARP network traffic.
* Establish normal IP-to-MAC mappings.
* Detect abnormal ARP Reply behavior.
* Identify devices attempting to impersonate trusted hosts.
* Investigate affected systems.
* Create a Splunk detection rule for ARP Spoofing activity.

---

## Environment

### Infrastructure

```text
DC01                Domain Controller
WIN11-01            Workstation
WIN11-02            Workstation
WIN11-03            Workstation
WIN11-04            Workstation
KALI01              Attacker Machine
SPLUNK01            SIEM Platform
```

### Security Platform

```text
Splunk Enterprise
```

### Network Range

```text
192.168.10.0/24
```

---

## Dataset Information

### Dataset Name

```text
SOC-HOMELAB-ARP-Spoofing-Realistic-700Events.jsonl
```

### Event Count

```text
700 Events
```

### Dataset Composition

```text
550 Normal ARP Requests

120 Normal ARP Replies

30 Malicious ARP Replies
```

### Fields

```text
timestamp
event_type
operation
sender_ip
sender_mac
target_ip
target_mac
sensor
```

---

## Investigation Methodology

### Step 1 – Review ARP Traffic

Understanding the available fields and overall traffic behavior.
<img width="1908" height="810" alt="image" src="https://github.com/user-attachments/assets/056d3462-76d0-42fd-ac5c-a3db19cfdd1f" />

### Step 2 – Build Baseline
<img width="1914" height="656" alt="image" src="https://github.com/user-attachments/assets/4693c118-8200-4335-9bfd-e417802a8d18" />

### Step 3 – Detect Anomalies
<img width="1915" height="561" alt="image" src="https://github.com/user-attachments/assets/18a66ba8-20c9-4c9e-87a4-5ed3d145b397" />

### Step 4 – Investigate Suspicious Activity
<img width="1898" height="684" alt="image" src="https://github.com/user-attachments/assets/0a471ce7-357a-4182-b16a-370a381b1abc" />

### Step 5 – Identify Affected Hosts

<img width="1916" height="490" alt="image" src="https://github.com/user-attachments/assets/c3bf6e4a-db99-49c4-923f-e4cc77fe24b0" />


### Step 6 – Confirm Potential Attack
Objective

Validate collected evidence and assess impact.

Query 1 – Count Spoofed Events
<img width="1903" height="537" alt="image" src="https://github.com/user-attachments/assets/87d0ee53-4740-4c2c-a5b8-bbfdb995bb7f" />

Query 2 – Build Timeline
<img width="1916" height="452" alt="image" src="https://github.com/user-attachments/assets/4660a09b-e135-41ee-b906-81167a2b9817" />

Query 3 – First Seen / Last Seen
<img width="1909" height="448" alt="image" src="https://github.com/user-attachments/assets/ae32e6ae-4fc4-423f-8c9c-7183388ebb81" />

---
Confirmation Criteria
Same IP associated with multiple MAC addresses.
Repeated ARP Reply activity.
Multiple affected hosts.
Gateway IP impersonation observed.
## Detection Logic

Under normal conditions, a single IP address should be associated with a single MAC address.

### Expected

```text
192.168.10.1
↓
00:11:22:33:44:55
```

### Suspicious

```text
192.168.10.1
↓
00:11:22:33:44:55

192.168.10.1
↓
AA:BB:CC:DD:EE:FF
```

This behavior may indicate ARP Cache Poisoning or ARP Spoofing activity.

---

## Splunk Detection Query

```spl
index=arp operation=reply
| stats dc(sender_mac) as MAC_Count values(sender_mac) as MACs by sender_ip
| where MAC_Count > 1
```

---

## Investigation Queries

### Build Baseline

```spl
index=arp
| stats values(sender_mac) by sender_ip
```

### Review Suspicious Gateway Activity

```spl
index=arp sender_ip="192.168.10.1"
| table _time sender_ip sender_mac target_ip
| sort _time
```

### Identify Affected Hosts

```spl
index=arp sender_mac="AA:BB:CC:DD:EE:FF"
| stats values(target_ip) as Victims
```
## Indicators of Compromise (IOCs)

| Indicator | Value |
|------------|------------|
| Suspicious IP | 192.168.10.1 |
| Legitimate MAC | 00:11:22:33:44:55 |
| Rogue MAC | AA:BB:CC:DD:EE:FF |
| Victims | 192.168.10.101, 192.168.10.102, 192.168.10.103 |
---

## Findings

The investigation identified a gateway IP address associated with multiple MAC addresses.

Evidence showed that a rogue MAC address repeatedly claimed ownership of the gateway IP and targeted multiple hosts across the network.

### Indicators

* Multiple MAC addresses associated with the same IP.
* Repeated ARP Reply activity.
* Multiple affected hosts.
* Potential network traffic interception.

### Assessment

```text
Potential ARP Spoofing Activity Confirmed
```

---

## MITRE ATT&CK Mapping

### Tactic

```text
Credential ```

### Technique

```text
T1557 - Adversary-in-the-Middle
```

---
## Lessons Learned

- ARP traffic should be baselined before building detections.
- Multiple MAC addresses associated with a single IP can indicate ARP cache poisoning.
- Network-layer attacks may not be visible in Windows Security Logs.
- Splunk can be used effectively for network anomaly detection and investigation.

## Skills Demonstrated

* Security Monitoring
* Detection Engineering
* Network Traffic Analysis
* Splunk SPL
* Incident Investigation
* MITRE ATT&CK Mapping
* SOC Analyst Methodology
