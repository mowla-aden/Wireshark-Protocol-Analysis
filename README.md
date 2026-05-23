# Wireshark-Protocol-Analysis
 This is a beginner SOC/network analysis project that  teaches:

* packet analysis
* protocol behavior
* troubleshooting
* traffic baselining
* investigation thinking


#  TASK 1 — Protocol Analysis Fundamentals

## Purpose
Learn:
* what “normal traffic” looks like
* request → response behavior
* protocol expectations

## Important Wireshark filters

## Show all traffic

```
frame
```


## Filter by IP

```
ip.addr == 192.168.1.10
```

## Client → Server traffic
```
ip.src == 192.168.1.10
```

## Server → Client traffic

```
ip.dst == 192.168.1.10
```

## SOC focus
Learn:
* who initiated communication
* who responded
* timing patterns

# TASK 2 — ARP Analysis

## Display filter

```
arp
```

## ARP Request only

```
arp.opcode == 1
```

## ARP Reply only

```
arp.opcode == 2
```

## Find specific IP

```
arp.dst.proto_ipv4 == 192.168.1.1
```

## Find MAC address

```
eth.addr == 00:11:22:33:44:55
```

## SOC investigation purpose

Detect:

* ARP spoofing
* duplicate IPs
* unusual MAC mappings

# TASK 3 — ICMP Analysis

## Show ICMP traffic
```
icmp
```

## Echo Request (ping)

```
icmp.type == 8
```

## Echo Reply
```
icmp.type == 0
```

## Find latency

* Right click packet:
*Apply as Time Reference
*Then compare request/reply times.

## SOC use
Detect:
* connectivity issues
* ping sweeps
* reconnaissance

# TASK 4 — TCP Analysis

## Show TCP traffic
```
tcp
```

## SYN packets
```
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

## SYN-ACK packets
```
tcp.flags.syn == 1 && tcp.flags.ack == 1
```

## ACK packets
```
tcp.flags.ack == 1
```

## TCP Reset
```
tcp.flags.reset == 1
```

## Follow TCP stream

Right click packet →

Follow → TCP Stream


## Detect retransmissions
```
tcp.analysis.retransmission
```

## SOC purpose
Detect:
* failed sessions
* scans
* resets
* abnormal handshakes

---

#  TASK 5 — UDP Analysis

## Show UDP
```
udp
```

## DNS traffic
```
udp.port == 53
```

## NTP traffic
```
udp.port == 123
```

## DHCP traffic
```
udp.port == 67 || udp.port == 68
```

## SOC focus
Learn:
* no handshake
* stateless communication
* fast protocols

#  TASK 6 — DNS Analysis

## Show DNS

```
dns
```

## DNS Queries only

```
dns.flags.response == 0
```

## DNS Responses only
```
dns.flags.response == 1
```

## Find domain
```
dns.qry.name contains "google"
```

## Find resolved IP
```
dns.a
```

## SOC purpose
Detect:
* malicious domains
* DNS tunneling
* beaconing
* suspicious lookups

# TASK 7 — HTTP Analysis

## Show HTTP
```
http
```

## GET requests
```
http.request.method == "GET"
```

## POST requests
```
http.request.method == "POST"
```

## HTTP response codes
```
http.response.code
```

## 404 errors
```
http.response.code == 404
```
## User-Agent

```
http.user_agent
```

## Follow HTTP stream
Right click →
```
Follow → HTTP Stream
```

## SOC purpose
Detect:
* web attacks
* scanning
* suspicious uploads
* malware downloads

#  TASK 8 — TLS / HTTPS Analysis
# Show TLS traffic

```
tls
```

# TLS handshake
```
tls.handshake
```

# Certificates
```
tls.handshake.certificate
```

# Server Name Indication (SNI)

```
tls.handshake.extensions_server_name
```

# TLS versions

```
tls.record.version
```
# SOC purpose
Understand:
* encrypted communication
* visible metadata
* certificate usage

# TASK 9 — Streams & Conversations

## Follow TCP stream

Right click →

```text id="’wini60"
Follow → TCP Stream
```

# Follow UDP stream

```text id="’wini61"
Follow → UDP Stream
```

# Conversation statistics

Menu:

```text id="’wini62"
Statistics → Conversations
```

---

# Endpoints

```text id="’wini63"
Statistics → Endpoints
```


# SOC purpose

Reconstruct:

* attacker communication
* sessions
* exfiltration

#  TASK 10 — Statistics Analysis

# Protocol hierarchy

Menu:

```text id="’wini64"
Statistics → Protocol Hierarchy
```

# IO Graphs

```text id="’wini65"
Statistics → IO Graphs
```
# Endpoints

```text id="’wini66"
Statistics → Endpoints
```
# Conversations

```text id="’wini67"
Statistics → Conversations
```
# SOC purpose
Validate:
* dominant protocols
* traffic spikes
* suspicious hosts
* anomalies

# TOP 15 ESSENTIAL FILTERS

```
arp
icmp
tcp
udp
dns
http
tls
tcp.flags.syn == 1
tcp.flags.reset == 1
http.request.method == "POST"
dns.flags.response == 0
tcp.analysis.retransmission
ip.addr == x.x.x.x
tcp.port == 80
udp.port == 53
```
