# NetDeflect

**NetDeflect** is an easy to use real-time DDoS detection and mitigation tool for Linux-based systems. It captures, analyzes, and classifies traffic in real-time, blocks malicious IPs based on attack signatures, provides live metrics and Discord webhook alerts.

---

### ✨ Features

- 📊 **Live Network Monitoring**: Real-time PPS, MB/s, and CPU tracking.
- 🚨 **Automated Detection**: Detects DDoS attacks using known protocol signatures and flags.
- 🔥 **Auto-Mitigation**: Blocks offending IPs using `iptables`, `ipset`, `ufw`, or blackhole routing.
- 🔍 **Traffic Analysis**: Uses `tcpdump` and `tshark` to capture and inspect attack patterns.
- 📁 **Organized Reports**: Stores pcap captures and analysis logs per incident.
- 📡 **Discord Webhook Support**: Sends alerts with attack stats and summaries.
- 🔄 **Self-Updating Checker**: Notifies you when a new version is available on GitHub.

---

### 🛠 Requirements

- Linux (Debian-based preferred)
- Python 3
- Packages `tcpdump`, `tshark`
- Firewall `iptables`, `ipset` (optional)
- PIP `psutil`, `requests`

---

### 🚀 Installation
(as root)

Ideally in a screen or tmux
```bash
apt install tcpdump tshark -y

git clone https://github.com/0vm/NetDeflect
cd NetDeflect

pip install psutil requests

python3 netdeflect.py
```
### On first use, you will need to run `netdeflect.py` several times to complete setup.

---

### ⚙️ Configuration

On first run, a `settings.ini` file and a `notification_template.json` will be created with defaults.

Your Discord webhook should be added to the `settings.ini` file.

The `notification_template.json` defines the Discord embed layout and can be fully customized.

Note: It's recommended to keep `enable_fallback_blocking` set to `False` to reduce the risk of false positives.

---

### 🧠 Attack Vector Matching

Attack signatures are loaded from `methods.json` and include detection for:

#### Reflection & Amplification Attacks
- DNS Amplification: ANY, RRSIG queries  
- NTP Reflection  
- SSDP Reflection  
- CLDAP Reflection  
- SNMP, MSSQL, SSDP, MDNS, Chargen Reflection  
- Memcached Reflection  
- STUN, CoAP, BACnet, QOTD, SIP, ISAKMP Reflection  
- TeamSpeak, Jenkins, Citrix, ARD, Plex, DVR, FiveM, Lantronix Reflections  
- BitTorrent Reflection  
- Apple serialnumberd Reflection  
- OpenVPN, DTLS, OpenAFS Reflection  
- vxWorks, Digiman, Crestron Reflection  
- XDMCP, IPMI Reflection  
- NetBIOS Reflection  
- NAT-PMP Reflection  
- GRE, ESP, AH Protocol Abuses  

---

#### Flooding Attacks
- UDP Flood  
- Hex UDP Flood  
- Flood of 0x00 / 0xFF  
- Known Botnet UDP Floods  
- UDPMIX DNS Flood  
- TCP Flag Abuses (SYN, ACK, RST, PSH combos)  
- TCP SYN, SYN-ACK, SYN-ECN, FIN, URG, etc.  
- Unset TCP Flags / malformed TCP  
- Fragmented IPv4 Floods  
- ICMP Floods / ICMP Dest Unreachable  
- Ookla Speedtest abuse  

---

#### Game Server & Protocol Exploits
- Source Engine Query (getstatus) Flood  
- ArmA Reflection (Ports 2302/2303)  
- TeamSpeak Status Flood  
- VSE (Valve Source Engine) Flood  
- FiveM Reflection  

---

#### TCP-Based Reflection Attacks

Mimic or abuse standard TCP-based services:

- HTTP/HTTPS Reflection  
- BGP Reflection  
- SMTP Reflection  

---

### 📦 Output Structure

```
netdeflect.py
settings.ini
notification_template.json
./application_data/
├── captures/           ← Raw .pcap traffic captures
├── ips/       ← IPs identified during attacks
├── attack_analysis/    ← Plaintext reports
```

---

### 📢 Notification Example

Sends alerts to Discord with information like:

- PPS & MBps before mitigation
- Blocked IP count
- Attack vector
- Mitigation status

![{C46C5365-14F3-4F7B-A4A7-6A3D45BDB9D4}](https://github.com/user-attachments/assets/8f0e07c6-8557-498f-9a74-89f6fd42750f)

---

# NOTE

If you do encounter any issues, debug has been left on for the first release, open an issue with as much info as you can.

If you have any suggestions, please feel free to open an issue!

---

### 🧾 License

[MIT License](LICENSE)


## Tags for SEO
ddos-protection network-security anti-ddos ddos-mitigation network-monitor traffic-analysis ip-blacklisting linux-security packet-filtering cyber-defense network-protection attack-detection traffic-filtering dos-protection network-monitoring-tool linux-firewall python-security tcp-ip-security attack-signature-detection real-time-monitoring blackhole-routing iptables ufw ipset packet-analysis traffic-thresholds bandwidth-monitoring pps-detection mbps-monitoring protocol-analysis server-protection web-server-security game-server-protection vps-security dedicated-server-protection hosting-security cloud-security online-service-protection infrastructure-security high-availability service-continuity automated-defense ip-blocking firewall-management attack-fingerprinting signature-based-detection threshold-based-detection adaptive-protection attack-pattern-recognition security-automation incident-response intrusion-detection alert-system discord-notifications webhook-alerts sysadmin-tools devops-security infrastructure-protection security-automation network-administration linux-administration server-hardening self-hosted-security open-source-security cybersecurity-tool network-diagnostics traffic-visualization security-monitoring network-reliability syn-flood-protection udp-flood-protection icmp-flood-protection http-flood-protection amplification-attack-protection reflection-attack-protection botnet-protection volumetric-attack-protection protocol-attack-protection application-layer-protection mixed-vector-protection linux-tool command-line-utility python-application networking-tool tcpdump-integration tshark-integration ipv4-security layer-3-protection layer-4-protection udp-protection tcp-protection packet-inspection network-traffic-control
