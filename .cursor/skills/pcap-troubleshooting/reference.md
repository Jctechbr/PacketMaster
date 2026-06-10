# Display Filter Quick Reference

## Noise removal

```
!(arp or dhcp or mdns or ssdp or browser)
```

## TCP problems

```
tcp.analysis.retransmission
tcp.analysis.fast_retransmission
tcp.analysis.duplicate_ack
tcp.analysis.zero_window
tcp.analysis.window_full
tcp.analysis.out_of_order
tcp.flags.reset == 1
```

## Latency

```
tcp.analysis.ack_rtt > 0.1
tcp.analysis.initial_rtt > 0.05
tcp.time_delta > 0.5
```

## Flow-specific

```
ip.addr == 10.0.0.1 and ip.addr == 10.0.0.2
ip.addr == 10.0.0.1 and ip.addr == 10.0.0.2 and tcp.port == 443
```

## Useful tshark fields for pm_extract_fields

```
frame.number
frame.time_relative
ip.src
ip.dst
tcp.srcport
tcp.dstport
tcp.analysis.ack_rtt
tcp.analysis.initial_rtt
tcp.analysis.flags
tls.handshake.extensions_server_name
dns.qry.name
```

## 802.11 Wi-Fi (monitor-mode captures only)

Requires radiotap + 802.11 headers. **Not available in Catalyst EPC/SPAN captures.**

### Start here

Use `pm_wifi_quick_scan` — then `pm_wifi_client_analysis` or `pm_wifi_roaming_analysis`.

### Most-used filters

```
wlan.fc.retry == 1
wlan.fc.retry == 1 && wlan.fc.tods == 1
wlan.fc.retry == 1 && wlan.fc.fromds == 1
wlan.addr == aa:bb:cc:dd:ee:ff
wlan.bssid == aa:bb:cc:dd:ee:ff
wlan_mgt.ssid == "MyNetwork"
```

### Join / disconnect

```
wlan.fc.type_subtype == 4 || wlan.fc.type_subtype == 5
wlan.fc.type_subtype == 8
wlan.fc.type_subtype == 0 || wlan.fc.type_subtype == 1
wlan.fc.type_subtype == 11
wlan.fc.type_subtype == 12
wlan.fc.type_subtype == 10
eapol
eap
```

### Roaming (802.11k/v)

```
wlan.fixed.action_code == 4
wlan.fixed.action_code == 5
wlan.fixed.action_code in {4, 5}
wlan.fixed.action_code in {7, 8}
```

Use `wlan.fixed.action_code` — not deprecated `wlan.rm.action_code`.

### RF

```
radiotap.dbm_antsignal < -75
radiotap.channel.freq == 5180
```

### Hide beacon noise

```
!(wlan.fc.type_subtype == 8)
```

## Wired Ethernet / L3 (EPC, SPAN, tap — primary PacketMaster use case)

### Tier 1 — daily troubleshooting

```
ip.addr == 10.0.0.50
ip.addr == 10.0.0.1 and ip.addr == 10.0.0.2
eth.addr == aa:bb:cc:dd:ee:ff
tcp.port == 443
udp.port == 53
!(arp or dhcp or mdns or ssdp or browser)
```

### DHCP / new device discovery

```
bootp
bootp.option.dhcp == 1
bootp.option.dhcp == 3
bootp || arp
```

### ARP / L2 discovery

```
arp
eth.dst == ff:ff:ff:ff:ff:ff
(eth.dst[0] & 1)
(eth.dst[0] & 1) && !(eth.dst == ff:ff:ff:ff:ff:ff)
```

### DNS (correct query vs response — Ask Wireshark gotcha)

```
dns.flags & 0x8000 == 0x0000
dns.flags & 0x8000 == 0x8000
dns.flags.response == 0
dns.flags.response == 1
dns.qry.name contains "example"
```

Do **not** use `dns.flags == 0x0100` for queries — bit mask required.

### VLAN / Q-in-Q

```
vlan
vlan.id == 100
vlan.id == 100 and vlan.id == 200
ieee8021ad.id == 129
```

Q-in-Q: both tags share field name `vlan.id`; match outer+inner with `and`.
S-tag only (802.1ad): `ieee8021ad.id == <vid>`.

### Cisco / infrastructure protocols

```
stp
cdp
lldp
eth.type == 0x88cc
hsrp
vrrp
igmp
eapol
eap
```

CDP multicast: `01:00:0c:cc:cc:cc` | LLDP: `01:80:c2:00:00:0e`.

### ICMP / path problems

```
icmp.type == 3
icmp.type == 11
icmp.type == 3 or icmp.type == 11
icmpv6.type == 1 or icmp.type == 3
ip.flags.mf == 1 or ip.frag_offset > 0
```

ICMP errors in tunneled traffic: `count(ip.addr) > 2`.

### Security / auth

```
tls.handshake.type == 1
tls.alert
http.request.method == "POST"
http.authorization
ftp.request.command == USER || ftp.request.command == PASS
```

## Corner cases and filter gotchas (forums + Wireshark docs)

### Excluding a host (classic mistake)

Wrong for "exclude host X":
```
ip.addr != 10.0.0.5
```

Correct (Wireshark 3.6+ `!=` is strict on multi-value fields):
```
!(ip.addr == 10.0.0.5)
```

Exclude traffic **to/from** a subnet (external traffic hunt):
```
ip.addr ~= 10.0.0.0/8
```
(`~=` / `any_ne` = old "any not equal" semantics; `!==` in newer Wireshark.)

### IP-in-IP / nested headers

```
ip.addr#1 == 1.1.1.1
ip.addr#2 == 10.0.0.1
count(ip.addr) > 2
```

### Fragmentation invisible under `icmp` filter

Filtering `icmp` alone hides IP fragments. Use conversation filter or:
```
ip.addr == <host> and (icmp or ip.flags.mf == 1 or ip.frag_offset > 0)
```

### Mixed VLAN tagging (capture filter — if capturing live)

Display filters handle dissection; capture BPF needs:
```
icmp or (vlan and icmp)
not (ip or (vlan and ip))
ether proto 0x88b8 or (vlan and ether proto 0x88b8)
```
Order matters for BPF `vlan` — see Wireshark blog on offsets.

### Asymmetric routing / firewall symptoms

```
tcp.analysis.lost_segment
tcp.analysis.ack_lost_segment
tcp.flags.syn == 1 && tcp.flags.ack == 0
tcp.flags.reset == 1
```

Compare captures from **both** path directions; one-sided SYN or RST is a red flag.

### Vendor OUI hunt (unknown device on wire)

```
eth.addr[0:3] == 00:1a:e8
```

### Useful with pm_extract_fields on wired captures

```
eth.src
eth.dst
vlan.id
ip.ttl
ip.id
icmp.type
icmp.code
bootp.option.hostname
dhcp.option.hostname
cdp.deviceid
lldp.chassis.id
```
