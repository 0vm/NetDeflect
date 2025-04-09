# NetDeflect DDoS Mitigation v2.0

**NetDeflect** is an advanced DDoS mitigation and detection tool for Linux-based systems. It captures, analyzes, and classifies traffic in real-time, blocks malicious IPs based on attack signatures, provides live metrics, and sends Discord webhook alerts to keep you informed of any attacks.

---

### 📽️ Demo
![quickdemo](https://github.com/user-attachments/assets/1b6061e4-e422-4edc-b8e2-de91bfb28b91)

<details>
<summary>Demo Video</summary>

https://github.com/user-attachments/assets/2fb581f6-7f8b-4200-8feb-82b43949c464

</details>

<details>
<summary>Unknown Attack Detection</summary>



https://github.com/user-attachments/assets/7f1beb7a-cab0-4565-b881-c19d3e40dd83


</details>

---

### ✨ Features

- 📊 **Live Network Monitoring**: Real-time PPS, MB/s, and CPU tracking.
- 🚨 **Intelligent Detection**: Identifies DDoS attacks using known protocol signatures, flags, and automatically detects new attack patterns.
- 🔥 **Comprehensive Mitigation**: Blocks offending IPs using `iptables`, `ipset`, `ufw`, or blackhole routing.
- 🔍 **Advanced Traffic Analysis**: Uses `tcpdump` and `tshark` to capture and inspect attack patterns with automatic pattern detection.
- 📁 **Organized Reports**: Stores pcap captures and detailed analysis logs for every incident.
- 📡 **Discord Webhook Integration**: Sends detailed alerts with attack stats, mitigation results, and summaries.
- 🔄 **Self-Updating**: Notifies you when a new version is available on GitHub.
- 🌐 **External API Integration**: Connect to external firewall services and security tools via configurable API endpoints.
- 🧠 **Auto-Pattern Detection**: Identifies and learns new attack patterns automatically.

---

### 🛠 Requirements

- Linux (Debian-based preferred)
- Python 3
- Packages: `tcpdump`, `tshark`
- Firewall: `iptables`, `ipset` (optional)
- PIP packages: `psutil`, `requests`

---

### 🚀 Installation
(as root)

Ideally in a screen or tmux session:
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

#### New Configuration Options in v2.0:

- **Advanced Mitigation Settings**:
  - `enable_fallback_blocking`: Control whether to block IPs when no specific attack signature is identified.
  - `block_other_attack_contributors`: Block top traffic contributors for unclassified attack types.
  - `enable_pattern_detection`: Automatically detect and identify common attack patterns.
  - `block_autodetected_patterns`: Choose whether to block IPs using newly detected patterns.
  - `contributor_threshold`: Minimum traffic percentage to consider an IP as malicious.
  - `max_pcap_files`: Control how many PCAP files to retain for historical analysis.

- **External Firewall API Integration**:
  - Connect to external security services with comprehensive configuration options.
  - Multiple authentication methods: bearer token, basic auth, header-based.
  - Flexible request formatting with customizable templates.
  - Batch processing options for efficient IP submission.

---

### 🧠 Attack Detection Methodology

NetDeflect v2.0 uses a multi-layered approach to detect attacks:

1. **Signature-based Detection**: Matches traffic against known attack patterns.
2. **Volume-based Detection**: Monitors traffic thresholds (PPS, MB/s).
3. **Automatic Pattern Discovery**: Identifies new attack patterns by analyzing traffic behavior.
4. **Contributor Analysis**: Identifies IPs contributing abnormally high traffic volumes.

Attack signatures are categorized into three types:
- **Spoofed IP Attacks**: Reflection and amplification attacks with spoofed source IPs.
- **Valid IP Attacks**: Direct attacks where the source IP is legitimate.
- **Other Attacks**: Specialized attack types that require custom handling.

---

### 📦 Output Structure

```
netdeflect.py
settings.ini
notification_template.json
methods.json
./application_data/
├── captures/           ← Raw .pcap traffic captures
├── ips/                ← IPs identified during attacks
├── attack_analysis/    ← Detailed reports of each attack
├── new_detected_methods.json  ← Auto-detected attack patterns
```

---

### 📢 Notification Example

Sends alerts to Discord with enhanced information:

- PPS & Mbps before mitigation
- Blocked IP count
- Attack vector and category
- Mitigation status
- Blocking strategy used

![{DiscordExample}](https://github.com/user-attachments/assets/58bc3755-5e1b-4eb0-99c6-c2cc79744a42)

---

### 🔗 External API Integration

NetDeflect v2.0 can integrate with external security services:

- Send blocked IPs to third-party firewalls or security services
- Multiple sending modes: single, batch, or all IPs at once
- Customizable request formatting
- Support for various authentication methods

Example configuration:
```ini
[external_firewall]
enable_api_integration=True
api_endpoint=https://api.example.com/firewall/block
auth_method=bearer
auth_token=your_api_token_here
sending_mode=batch
max_ips_per_batch=10
```

---

### 🔍 Auto-Pattern Detection

The new pattern detection system automatically:

1. Analyzes traffic patterns during attacks
2. Identifies common hex patterns across multiple sources
3. Creates and saves new attack signatures
4. Optionally blocks IPs using these new patterns

This enables NetDeflect to learn and adapt to new attacks without manual intervention.

---

# NOTE
**Make sure to remove the services you use from methods.json, such as removing specific TCP flags or removing HTTP/1 reflection if you run a webserver.**

If you do encounter any issues, debug has been left on, open an issue with as much info as you can.

If you have any suggestions, please feel free to open an issue!

---

## Tags for SEO
ddos-protection network-security anti-ddos ddos-mitigation network-monitor traffic-analysis ip-blacklisting linux-security packet-filtering cyber-defense network-protection attack-detection traffic-filtering dos-protection network-monitoring-tool linux-firewall python-security tcp-ip-security attack-signature-detection real-time-monitoring blackhole-routing iptables ufw ipset packet-analysis traffic-thresholds bandwidth-monitoring pps-detection mbps-monitoring protocol-analysis server-protection web-server-security game-server-protection vps-security dedicated-server-protection hosting-security cloud-security online-service-protection infrastructure-security high-availability service-continuity automated-defense ip-blocking firewall-management attack-fingerprinting signature-based-detection threshold-based-detection adaptive-protection attack-pattern-recognition security-automation incident-response intrusion-detection alert-system discord-notifications webhook-alerts sysadmin-tools devops-security infrastructure-protection security-automation network-administration linux-administration server-hardening self-hosted-security open-source-security cybersecurity-tool network-diagnostics traffic-visualization security-monitoring network-reliability syn-flood-protection udp-flood-protection icmp-flood-protection http-flood-protection amplification-attack-protection reflection-attack-protection botnet-protection volumetric-attack-protection protocol-attack-protection application-layer-protection mixed-vector-protection linux-tool command-line-utility python-application networking-tool tcpdump-integration tshark-integration ipv4-security layer-3-protection layer-4-protection udp-protection tcp-protection packet-inspection network-traffic-control
