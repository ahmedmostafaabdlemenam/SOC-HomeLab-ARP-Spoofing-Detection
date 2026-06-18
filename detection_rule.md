# ARP Spoofing Detection Rule

## Detection Name

Potential ARP Spoofing Activity

---

## Description

This detection identifies potential ARP Spoofing (ARP Cache Poisoning) activity by monitoring ARP Reply traffic and detecting IP addresses associated with multiple MAC addresses.

Under normal network conditions, a single IP address should consistently map to a single MAC address. Multiple MAC addresses observed for the same IP may indicate an attempt to impersonate a trusted device such as the default gateway.

---

## Attack Overview

ARP Spoofing is a Layer 2 attack in which an attacker sends forged ARP replies to associate their MAC address with another host's IP address.

This attack can enable:

* Man-in-the-Middle (MITM)
* Traffic Interception
* Session Hijacking
* Credential Theft
* Network Manipulation

---

## Data Source

Network ARP Traffic Logs

### Fields Used

```text
sender_ip
sender_mac
target_ip
target_mac
operation
timestamp
```

---

## Detection Logic

Identify ARP Reply events where a single IP address is associated with multiple MAC addresses.

Expected Behavior:

```text
192.168.10.1
↓
00:11:22:33:44:55
```

Suspicious Behavior:

```text
192.168.10.1
↓
00:11:22:33:44:55

192.168.10.1
↓
AA:BB:CC:DD:EE:FF
```

---

## Splunk Detection Query

```spl
index=arp operation=reply
| stats dc(sender_mac) as MAC_Count values(sender_mac) as MACs by sender_ip
| where MAC_Count > 1
```

---

## Alert Configuration

### Alert Name

Potential ARP Spoofing Activity

### Severity

High

### Trigger Condition

A single sender_ip is associated with multiple sender_mac values.

---

## Investigation Steps

### 1. Review Suspicious IP

```spl
index=arp sender_ip="<Suspicious_IP>"
| table _time sender_ip sender_mac target_ip
| sort _time
```

---

### 2. Identify Rogue MAC Address

```spl
index=arp sender_ip="<Suspicious_IP>"
| stats count by sender_mac
```

---

### 3. Identify Affected Hosts

```spl
index=arp sender_mac="<Rogue_MAC>"
| stats values(target_ip) as Victims
```

---

### 4. Build Timeline

```spl
index=arp sender_mac="<Rogue_MAC>"
| table _time sender_ip target_ip
| sort _time
```

---

## Example Finding

### Suspicious IP

```text
192.168.10.1
```

### Observed MAC Addresses

```text
00:11:22:33:44:55
AA:BB:CC:DD:EE:FF
```

### Assessment

Potential ARP Cache Poisoning targeting the default gateway.

---

## MITRE ATT&CK Mapping

### Tactic

Credential Access

### Technique

T1557 - Adversary-in-the-Middle

---

## Analyst Notes

This detection should be validated against known infrastructure changes such as:

* Gateway Replacement
* Network Interface Changes
* Virtual Network Reconfiguration

If no legitimate infrastructure changes are identified, investigate for potential Man-in-the-Middle activity.
