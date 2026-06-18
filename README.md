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

### Step 2 – Build Baseline

Identify normal IP-to-MAC mappings across the environment.

### Step 3 – Detect Anomalies

Search for IP addresses associated with multiple MAC addresses.

### Step 4 – Investigate Suspicious Activity

Review suspicious ARP Reply traffic and validate findings.

### Step 5 – Identify Affected Hosts

Determine which hosts received spoofed ARP responses.

### Step 6 – Confirm Potential Attack

Validate collected evidence and assess impact.

---

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
Credential Access
```

### Technique

```text
T1557 - Adversary-in-the-Middle
```

---

## Skills Demonstrated

* Security Monitoring
* Threat Hunting
* Detection Engineering
* Network Traffic Analysis
* Splunk SPL
* Incident Investigation
* MITRE ATT&CK Mapping
* SOC Analyst Methodology

---

## Repository Structure

```text
SOC-HomeLab-ARP-Spoofing-Detection

├── Dataset
│   └── SOC-HOMELAB-ARP-Spoofing-Realistic-700Events.jsonl

├── Detection
│   └── detection_rule.md

├── Investigation
│   └── arp_spoofing_investigation.md

├── Screenshots
│   ├── 01_data_upload.png
│   ├── 02_baseline.png
│   ├── 03_detection.png
│   └── 04_investigation.png

└── README.md
```
