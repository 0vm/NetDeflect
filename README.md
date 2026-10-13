# 🛡️ NetDeflect

**NetDeflect** is open-source DDoS protection for Linux servers. It watches the traffic reaching your server, recognises an attack as it builds, works out exactly what kind of attack it is, and drops it inside the Linux kernel while your players, users and services keep working. Then it tells you what happened on Discord.

It's built for game servers (FiveM, Minecraft, CS2, Rust, SA-MP, TeamSpeak and more), WireGuard and OpenVPN servers, and anything else exposed to the internet, from a one-core VPS to a 100G edge.

One command to install. Nothing to compile.

> 👋 **NetDeflect is made for every skill level.** If you've never touched a firewall, the installer asks five simple questions and sets everything up for you. If you run your own network, every detail can be tuned. The first half of this page is all most people need. The **For advanced users** part at the bottom is completely optional, so feel free to ignore it.

---

<a id="demo"></a>
## 📽️ Demo

<p>
<img width="72%" alt="NetDeflect mitigating an attack" src="https://github.com/user-attachments/assets/56a5ed68-dd9c-48a4-b482-20c7ae0d98a4" /><img width="26%" alt="NetDeflect alert" src="https://github.com/user-attachments/assets/38a3fcd9-6bf7-436d-814e-eec42f7a6f41" />
</p>

https://github.com/user-attachments/assets/219d8a48-3bce-46f7-9a65-ffadbbb256c3

<details>
<summary>Older demos (v2)</summary>

![quickdemo](https://github.com/user-attachments/assets/1b6061e4-e422-4edc-b8e2-de91bfb28b91)

https://github.com/user-attachments/assets/2fb581f6-7f8b-4200-8feb-82b43949c464

https://github.com/user-attachments/assets/8ac4f69f-974f-4bde-91dd-708f092744d2

**Unknown attack detection**

https://github.com/user-attachments/assets/7f1beb7a-cab0-4565-b881-c19d3e40dd83

</details>

---

<a id="installation"></a>
## 🚀 Installation

You need a Linux server and root access.

```bash
git clone https://github.com/0vm/NetDeflect && cd NetDeflect
sudo bash install.sh
```

That's it. The installer grabs what it needs (Python, nftables, iproute2), asks whether you want to run it in the current folder or install it as a service that starts on boot, then asks you five quick questions:

1. Which network interface to protect (it guesses for you)
2. Your game or VPN ports
3. Your Discord webhook
4. Your machine size (VPS, server or enterprise)
5. Whether to start in watch-only mode

Check on it any time with:

```bash
sudo systemctl status netdeflect
sudo journalctl -u netdeflect -f
```

<details>
<summary>Manual install</summary>

```bash
sudo apt install python3 python3-psutil python3-requests nftables iproute2
git clone https://github.com/0vm/NetDeflect && cd NetDeflect
sudo python3 netdeflect.py --setup       # writes settings.ini
sudo python3 netdeflect.py               # runs in the foreground
```

On Fedora, Rocky or AlmaLinux: `dnf install python3 python3-psutil python3-requests nftables iproute`

</details>

> 💡 **First day tip:** start in watch-only mode. NetDeflect reports exactly what it *would* block without blocking anything, so you can check it suits your traffic before switching it on.

---


## 📑 Contents

**Getting started** (everyone)

- [📽️ Demo](#demo)
- [🚀 Installation](#installation)
- [✨ Features](#features)
- [🎮 Setting it up for your server](#setup)
- [🧠 How it works](#how-it-works)
- [📢 Discord alerts](#alerts)
- [🛠️ Commands](#commands)
- [⚙️ Settings](#settings)
- [🗑️ Uninstalling](#uninstalling)
- [❓ FAQ](#faq)
- [⚠️ Good to know](#good-to-know)

**For advanced users** (optional, skip this if you just want your server protected)

- [📋 Full feature list](#full-features)
- [⚡ Does NetDeflect use XDP or eBPF?](#xdp)
- [🔬 How it works in detail](#how-it-works-detail)
- [🎮 Protecting game and VPN ports in detail](#game-vpn-detail)
- [🪞 Reflection and amplification attacks](#reflection)
- [📡 Large links: sFlow, NetFlow and 10G/100G](#large-links)
- [🛠️ All commands](#all-commands)
- [⚙️ Full configuration](#full-config)
- [📜 Attack signatures](#signatures)
- [🔌 Alerts and integrations](#integrations)
- [📈 Metrics](#metrics)
- [🌐 Upstream protection with BGP](#bgp)
- [📦 Files](#files)
- [❓ Advanced FAQ](#advanced-faq)
- [🚧 Limitations](#limitations)

---

<a id="features"></a>
## ✨ Features

- 📊 Live monitoring of packets per second, bandwidth and CPU, with a live status screen
- 🚨 110 built-in attack signatures, matched on real packet fields (not text guessing)
- 🧠 Learns attacks nothing recognises by fingerprinting them (source port, TTL, flags, length, payload) and drops them automatically
- 🔥 Drops attacks in the kernel with nftables, so NetDeflect itself stays light even during a huge flood
- 🪞 Stops reflection and amplification (NTP, DNS, memcached, SSDP, CLDAP and 50+ more) by the shape of the reply, not just the port, so your own services are never mistaken for an attack
- 🎮 Game and VPN protection: learns your real players and lets them through first, and caps everyone else during an attack
- 🔐 WireGuard and OpenVPN validation drops anything that isn't a real VPN packet
- 🕵️ Never blocks faked addresses, so an attacker can't trick it into blocking someone innocent
- ⚡ Optional XDP fast path for busy 10G+ servers
- 📡 sFlow, NetFlow and BGP support for networks with their own routers
- 💬 Discord alerts coloured by result, with a plain-English summary and clear advice when you need to act. Slack, Teams and Mattermost too
- 📁 A report, address list and packet capture saved for every attack
- 📈 Prometheus metrics, a JSON event log, your own script hook and external firewall API support
- 🔄 Tells you when a new version is out

Want every detail? See the [full feature list](#full-features).

---

<a id="setup"></a>
## 🎮 Setting it up for your server

Most servers only need two things in `settings.ini`: your webhook and `[services] ports`.

| Your server | Set `[services] ports` to |
|---|---|
| UDP game server (Rust, ARK, Unturned, SA-MP, FiveM game port) | `28015/udp` |
| Source engine (CS2, Garry's Mod, TF2) | `27015/both` |
| Minecraft Java | `25565/tcp` |
| Minecraft Bedrock | `19132/udp` |
| FiveM (game and HTTP on one port) | `30120/both` |
| WireGuard | `51820/udp:wireguard` |
| OpenVPN over UDP | `1194/udp:openvpn` |
| Several at once | `27015/both, 51820/udp:wireguard` |

**Using a game panel with Docker (Pterodactyl, Pelican)?** Leave `network_interface = auto` and list your public ports. Docker's internal networks aren't touched.

**Got a VPN or GRE tunnel in front of your game server?** Run NetDeflect on the front server. Tunnels are detected and trusted automatically.

**Running a website?** Leave `[services]` empty or list `80/tcp, 443/tcp`.

After editing `settings.ini`, apply it with `sudo systemctl reload netdeflect`.

---

<a id="how-it-works"></a>
## 🧠 How it works

1. **Watch.** Every second NetDeflect checks how much traffic is arriving. This costs almost nothing.
2. **Sample.** When traffic crosses your thresholds, it grabs a sample of packets to inspect. CPU use stays the same however big the attack is.
3. **Recognise.** It matches the sample against its signatures. If nothing matches, it fingerprints the attack itself.
4. **Respond.** It picks the right response for the attack type:

| Attack | What NetDeflect does |
|---|---|
| Reflection / amplification | Drops it and blocks every reflector server used |
| UDP, TCP and protocol floods | Drops the pattern (the sources are faked, so blocking them would be pointless) |
| SYN floods | Drops forged SYNs, turns on SYN cookies, limits each source |
| DNS, ICMP and game query floods | Limits each source so real users keep working |
| Botnet and stresser payloads | Blocks the attacking machines for a set time |
| Something new | Learns its fingerprint and drops it if certain, otherwise reports it |

5. **Report.** It measures how much is being dropped, sends you an alert, and saves a report.
6. **Recover.** Once traffic is back to normal for a couple of minutes, the attack is over, you get a summary, and blocks expire on their own.

**Your game and VPN ports get extra care.** While things are quiet, NetDeflect learns who your real players are. During an attack they go first, while everyone else gets a small allowance each and a fixed total, so a flood from thousands of fake addresses can't fill your port and new players can still join.

---

<a id="alerts"></a>
## 📢 Discord alerts

Add your Discord webhook to `[notification] webhook_url` in `settings.ini`, then run `sudo python3 netdeflect.py --test-webhook` to see a sample.

<img width="734" height="602" alt="image" src="https://github.com/user-attachments/assets/116c66cd-1071-402d-93d1-395b655b7514" />


Every alert includes:

- 🟢 🟠 🔴 A colour showing how it's going: mitigated, partially mitigated, or not yet stopped
- 📝 A one-line summary in plain English, like *"Zero-fill UDP Flood against 203.0.113.10 port 53. Dropping 68,347 pps (62% of incoming) in the kernel."*
- 📈 Incoming traffic, how much is being dropped, and what's still getting through
- 🎯 Which ports are being hit, the attack types, and any learned pattern
- 🚫 What was blocked
- ⚠️ "Action needed", but only when something's wrong, telling you exactly what to change

You get an alert when an attack starts, when a new attack type shows up, and a summary when it ends, so your channel doesn't get spammed.

| Setting | What it does |
|---|---|
| `discord_mention` | Ping on attack alerts, e.g. `@here` or a role (`<@&ROLE_ID>`) |
| `text_webhook_url` | Also send alerts to Slack, Teams or Mattermost |
| `discord_style = template` | Use your own `notification_template.json` layout instead |

---

<a id="commands"></a>
## 🛠️ Commands

| Command | What it does |
|---|---|
| `sudo python3 netdeflect.py` | Run in the foreground with the live status screen |
| `--setup` | Guided setup |
| `--selftest` | Check everything is installed and set up right |
| `--test-webhook` | Send a sample Discord alert |
| `--dry-run` | Watch-only: detect and report, block nothing |
| `--block 1.2.3.4` | Block an address (add `--for SECONDS` for a time limit) |
| `--unblock 1.2.3.4` | Remove a block |
| `--list-blocks` | See what's blocked |
| `--stats` | How many packets have been dropped |

Block commands work while NetDeflect is running. More in [All commands](#all-commands).

---

<a id="settings"></a>
## ⚙️ Settings

Every option is explained inside `settings.ini`. The ones you're most likely to change:

| Setting | Default | What it means |
|---|---|---|
| `[capture] network_interface` | `auto` | Which interface to protect |
| `[triggers] pps_threshold` | 15000 | Packets per second that count as an attack |
| `[triggers] mbps_threshold` | 30 | Megabytes per second that count as an attack (240 Mbit/s) |
| `[services] ports` | empty | Your game and VPN ports |
| `[firewall] block_timeout` | 3600 | How long a block lasts, in seconds |
| `[firewall] enable_ban` | True | Set to False for watch-only mode |
| `[notification] webhook_url` | empty | Your Discord webhook |

Set the thresholds a little above your busiest normal traffic. The live status screen shows you what normal looks like.

---

<a id="uninstalling"></a>
## 🗑️ Uninstalling

```bash
sudo systemctl disable --now netdeflect
sudo rm /etc/systemd/system/netdeflect.service
sudo python3 /opt/NetDeflect/netdeflect.py --teardown
sudo rm -r /opt/NetDeflect
```

Stopping the service already removes NetDeflect's rules. `--teardown` cleans up anything left over (only the rules, sets, routes and XDP programs NetDeflect created).

---

<a id="faq"></a>
## ❓ FAQ

**Will it block my players?**
No. Players are never blocked by address unless they send botnet traffic. During an attack, your learned players go first. Try watch-only mode first if you want to be sure.

**Does it work with Docker and game panels?**
Yes. Only the interfaces you choose are filtered, and Docker's internal networks are left alone.

**Will it slow my server down?**
No. When there's no attack it uses almost no CPU, and during an attack the kernel does the dropping, not Python.

**What happens if I stop NetDeflect?**
Its firewall rules are removed and your server goes back to normal. Nothing is left behind.

**How do I see what's happening?**
Run `sudo python3 netdeflect.py` for the live status screen, or follow `journalctl -u netdeflect -f`. Reports are in `application_data/attack_analysis/`.

**An attack still knocked my server offline.**
If an attack is bigger than your server's internet connection, the connection is full before the traffic even reaches your server, and nothing running on the server can fix that. Ask your host about upstream DDoS protection; NetDeflect works best alongside it.

---

<a id="good-to-know"></a>
## ⚠️ Good to know

- If an attack is bigger than your internet connection, it has to be stopped upstream by your host or with BGP. No software on the server can stop a full pipe.
- An attack has to cross your thresholds before NetDeflect acts, so set them a little above your normal peak, not miles above it.
- An attack that randomises absolutely everything and matches no signature can't be dropped by pattern. On your `[services]` ports, lockdown still keeps it in check.
- If you run a service yourself that a signature could clash with (a web server and HTTP reflection, for example), disable that signature in `methods.json`.
- Linux only, and it needs root.

Found a bug or have an idea? Open an issue with as much detail as you can. Logs from `journalctl -u netdeflect` and the attack report help a lot.

---
---

# 🧪 For advanced users

> **Everything from here down is optional.** NetDeflect works out of the box with the settings the installer gives you. This part is for people who want to know exactly how it works, tune it, or run it on their own network. If that's not you, you can stop reading here. 🎉

---

<a id="full-features"></a>
## 📋 Full feature list

### Detection
- Live monitoring of packets per second, bandwidth and CPU on one or several interfaces, with a live status screen.
- Reads either live packets (built-in sniffer, tcpdump or tshark) or sampled flow telemetry from your router or switch: sFlow v5 and NetFlow v5/v9/IPFIX. Flow mode is how NetDeflect runs on 10G, 40G and 100G links without touching the data path, and the same classifier is used for both.
- Triggers on total packets per second, bandwidth, or both, plus optional per-protocol triggers (TCP, UDP, ICMP) for floods that hide inside normal total traffic.
- Precise packet classification on real header fields: protocol, ports, TCP flags (including ECN and reserved bits), TCP options (MSS, window), packet length, TTL, DSCP, ICMP type and code, fragment state, and payload bytes at an exact offset.
- 110 built-in attack signatures covering more than 50 reflection and amplification services, SYN/ACK/RST/FIN floods, crafted-packet floods, botnet and stresser payloads, game-server query floods and protocol abuse.
- Learns attacks no signature recognises. It fingerprints the whole packet (source port, TTL, TCP window, DSCP, TCP flags, length and payload) and builds the most specific rule that still covers the attack. A field only counts when several different sources share it, and normal traffic, single busy connections, established-connection flags and your own game protocol are never learned.
- SYN-flood fingerprinting: SYNs without an MSS option or with an impossible MSS are recognised as tool-generated and dropped outright.
- Carpet-bombing detection when an attack is spread across a whole range of your addresses.
- Pulse-wave detection: repeated on/off bursts keep protection up through the quiet gaps.
- Saturation detection from network-card and kernel drop counters, so you know when an attack is bigger than your connection.

### Mitigation
- Drops attacks inside the Linux kernel (nftables, or iptables with ipset), so NetDeflect itself stays light while the attack is dropped at full speed.
- Optional XDP fast path (`firewall_system = xdp`, via xdp-tools): banned source addresses are dropped in the NIC driver with XDP, before the packet reaches the kernel stack. nftables stays the authority; if xdp-tools or driver support is missing it falls back to nftables, so protection is never reduced.
- Never blocks forged addresses. Floods with fake sources are stopped by dropping the attack pattern and rate limiting each source, so an attacker cannot trick NetDeflect into blocking someone innocent.
- Confident learned patterns are dropped automatically while the attack runs (`autodetect_enforce`). A few heavy, stable sources behind a learned pattern are treated as confirmed bad actors and blocked by address.
- Blocks every reflection/amplification server used against you, and botnet machines, for a set time. Blocks expire on their own.
- Per-source rate limits for SYN floods, ICMP floods and query floods, so each real client keeps its own allowance.
- SYN cookies switched on automatically.
- Always-on clean-up of impossible traffic: port 0, packets claiming to come from your own server, IP fragment floods, and (optionally) private-range sources on a public interface.
- Optional overall limits per protocol for known-quiet servers.
- Blocks whole ranges automatically when many addresses from one /24 or /64 are attacking.
- Blocklist files and blocklist URLs (for example Spamhaus DROP) loaded into the kernel and refreshed automatically.
- Optional connection tracking extras: drop out-of-state ACK/RST floods, drop reflection replies you never asked for, and cap connections per address to stop slowloris-style attacks.
- Upstream blackholing over BGP (ExaBGP or your own script) for attacks bigger than your connection.
- Out-of-band mode (`firewall_system = bgp`): install no local rules at all and ask your upstream to drop the attacker prefixes over BGP and/or an external API. Pairs with sFlow/NetFlow so NetDeflect sits beside the traffic, not in it. If NetDeflect stops, the router keeps forwarding and the link stays up, so there is nothing to fail closed.

### Game server and VPN protection
- Declare your game and VPN ports once. Floods aimed at them are mitigated.
- Learns your real players and VPN users while things are quiet, and lets them through first during an attack.
- Lockdown during an attack: addresses that are not known players get a small allowance each and a small total allowance, so a flood from thousands of fake addresses cannot fill the port.
- WireGuard and OpenVPN validation: anything sent to those ports that is not a valid WireGuard or OpenVPN packet is dropped.
- Optional per-source limit and packet-size limits for each port.
- GRE, IPIP and WireGuard tunnels are detected automatically, their endpoints trusted and their protocols never treated as a flood.

### Safety
- Your gateway, your public IP, the DNS resolvers you use, your SSH session, private ranges and anything you whitelist are never blocked.
- Loopback, Docker bridges, VPN links and other internal interfaces are left untouched; only the interfaces you choose are filtered.
- A rule is only installed if the firewall can express it exactly; it is never widened into something that could drop normal traffic.
- Watch-only mode (`--dry-run` or `enable_ban = False`) reports exactly what would be blocked without blocking anything.
- Whole ruleset applied in one step, so protection never drops out while rules change. A rule the firewall rejects is removed and the rest still load. Rules are removed when NetDeflect stops.
- If a firewall restart or Docker removes NetDeflect's rules, they are put back within 30 seconds.
- Reports, captures and logs are rotated so they never fill the disk.
- Settings are checked on start; any mistake is listed clearly and nothing is overwritten.

### Alerts, reports and monitoring
- Discord alerts coloured by result (mitigated, partially mitigated, not yet mitigated, link saturated), with a plain-English summary, traffic and drop figures, target ports and protocol mix, each attack vector marked spoofed or real, learned patterns, unique source count, what was blocked, and an "Action needed" field only when something needs your attention.
- An end-of-attack summary with duration, peak, peak dropped, every attack type seen, rounds, start and end time and pulse-wave bursts.
- Slack, Microsoft Teams and Mattermost text alerts with the same information. Alerts are sent when an attack starts, when new attack types appear and when it ends, so your channel is not flooded.
- Run your own script on every attack with the full report as JSON (a few lines of `curl` forwards it to Discord, Telegram or a BGP tool).
- A text and JSON report for every attack, a CSV of the addresses involved, and a .pcap capture for analysis.
- Prometheus metrics (node_exporter textfile or a built-in `/metrics` page).
- JSON event log for SIEM tools.
- Send blocked addresses to an external firewall or provider API.

### Operations
- Guided setup (`--setup`) and a one-command installer with a systemd service.
- Profiles for a small VPS, a dedicated server or an enterprise fleet.
- Live block and unblock commands that do not disturb the running service.
- Reload settings and signatures without a restart (`systemctl reload`).
- Network interface detected automatically.
- Remembers learned clients, learned patterns and attack numbering across restarts.
- Update notice when a new release is available (can be turned off).

---

<a id="xdp"></a>
## ⚡ Does NetDeflect use XDP or eBPF?

Optionally, yes. Set `firewall_system = xdp` and NetDeflect loads xdp-tools' `xdp-filter` on your interface, so the source addresses it bans (reflectors, botnet sources, `--block` and `block_ips`) are dropped in the NIC driver with **XDP**, before the packet reaches the kernel's network stack. It needs the `xdp-tools` package and an interface whose driver supports XDP, with nothing for you to compile. If either is missing it falls back to skb/generic XDP and then to plain nftables, so protection is never reduced.

By default NetDeflect does not turn XDP on, because for most servers the nftables `prerouting` raw hook (before connection tracking) already drops at line rate for the pipe, needs no extra package and runs everywhere. Turn XDP on when you are dropping a lot of traffic on the host itself, typically a 10G+ box, and want the banned sources gone in the driver before they cost the stack anything.

What is and is not XDP here:

- **The drop of banned source addresses is real XDP,** in the NIC driver, via xdp-filter (native, skb/generic or hardware-offload mode). It holds a bounded working set (`xdp_max_entries`, at most 10000 per address family), heaviest sources first; nftables keeps the rest, and does all of the pattern and spoofed-source dropping, range bans and blocklist ranges, which a by-address XDP filter cannot express.
- **nftables stays the authority.** The XDP map is reconciled against nftables' bans every few seconds and on every change, so an address leaves XDP no later than it leaves nftables: when its ban expires, when you `--unblock` it, or after a crash (the service runs `--teardown` on stop, which unloads xdp-filter too). xdp-filter is loaded once; rule changes do not reload it.
- **XDP drops are counted.** `--stats`, reports and alerts include packets dropped in XDP. Because XDP runs before the packet sniffer, a round in which XDP drops the whole attack is reported as mitigated.
- xdp-filter keeps its map in the BPF filesystem; NetDeflect mounts it at `/sys/fs/bpf` if your system has not (containers, minimal VMs, WSL).
- **The classifier is not eBPF.** NetDeflect samples the traffic, works out the attack and decides what to ban in userspace, then hands the bans to XDP and nftables. The only BPF in the capture path is a classic (cBPF) tcpdump-style filter, which never drops anything.

---

<a id="how-it-works-detail"></a>
## 🔬 How it works in detail

1. **Watch.** Every second NetDeflect reads the packet and byte counters of the interfaces you protect. This costs almost nothing.
2. **Trigger.** When traffic crosses your thresholds, NetDeflect samples a limited number of packets (`packet_count`). Its CPU use depends on this number, not on the size of the attack.
3. **Recognise.** Each sampled packet is compared with the attack signatures. A signature counts as part of the attack when it matches enough of the sample. If nothing strong matches, the sample is fingerprinted to learn the attack.
4. **Respond.** Each signature belongs to a category that decides the response:

   | Category | Source address | Response |
   |---|---|---|
   | Reflection / amplification | Real server being abused | Drop the pattern, block every reflector seen |
   | TCP reflection | Real web server | Drop replies you never asked for (needs connection tracking), never block the server |
   | DNS and query floods | Forged | Per-source rate limit |
   | UDP / TCP / flag / protocol floods | Forged | Drop the pattern, never block addresses |
   | SYN flood | Forged | Drop forged SYNs (no MSS, impossible MSS, invalid flags), SYN cookies and per-source SYN limit |
   | ICMP flood | Forged | Per-source rate limit (ping keeps working) |
   | Fragment flood | Forged | Rate limit or drop fragments |
   | Out-of-state ACK/RST/FIN floods | Forged | Dropped by connection tracking (optional) |
   | Game server query floods | Forged | Per-source rate limit |
   | Botnet / stresser payloads | Real attacker | Block the addresses for a set time |
   | Unrecognised | Unknown | Learn the fingerprint; drop it if confident, otherwise report it |

5. **Measure.** NetDeflect reads the firewall's own drop counters to report how much is being dropped and how much still gets through, and checks the network card's drop counters to see whether the attack is bigger than the connection.
6. **Report.** Alerts go out, and a report, address list and capture are saved.
7. **Recover.** Once traffic stays normal for `holddown_seconds`, the attack is declared over, lockdown is lifted and a summary is sent. Blocks expire on their own.

### How unknown attacks are learned

When no signature explains the attack, NetDeflect groups the sample by protocol and destination port and looks at every header field: source port, TTL, TCP window, DSCP, TCP flags, packet length and payload. A field only counts as a marker when it dominates the attack (`autodetect_marker_pct`, 85% by default) and is shared by several different sources. Traffic from a single source, the flags every established connection sends (ACK, ACK+PSH, ACK+FIN), your learned clients and your normal peacetime traffic are never learned.

A pattern with two or more matching header fields, or a shared payload, is high confidence and is dropped automatically while the attack runs (`autodetect_enforce = True`). Lower-confidence patterns are reported and saved for you to review, unless you set `block_autodetected_patterns = True`.

### Why NetDeflect does not rely on connection tracking

The first line of defence keeps no per-connection state. Floods with fake source addresses create a new connection entry for every packet, so a defence built on connection tracking can be overwhelmed by the attack it is meant to stop. NetDeflect drops attack traffic before connection tracking sees it. The connection tracking extras are optional and run separately, after the stateless rules.

---

<a id="game-vpn-detail"></a>
## 🎮 Protecting game and VPN ports in detail

List your public ports in `[services] ports`. During an attack aimed at them:

1. **Invalid packets are dropped.** Ports marked `:wireguard` or `:openvpn` only accept packets of that protocol. Optional packet-size limits drop anything your game never sends.
2. **Known players go first.** While there is no attack, NetDeflect briefly samples traffic every `learn_interval` seconds. An address that sent to your port and received replies from it, in at least two separate samples, is remembered as a real client for `client_memory_hours`. Known clients are let through ahead of everything else.
3. **Lockdown.** Once an attack starts, and if at least `lockdown_min_clients` clients are known, everyone else is limited to `lockdown_rate_per_source` packets per second each and `lockdown_total_rate` in total. A flood from thousands of fake addresses is held to that total, while known players are unaffected and new players can still join within it.
4. **Attack patterns are still dropped.** Traffic that passes is still checked against the attack signatures. Patterns your known players send are never learned as an attack.

Outside an attack you can also set `rate_per_source` to cap any single address.

For finer control, give a service its own section:

```ini
[service:rust]
ports = 28015
protocol = udp
preset = game
rate_per_source = 300
min_length = 40
max_length = 1300
lockdown = True
known_client_rate = 2000
```

Presets: `game` (default), `wireguard`, `openvpn`, `minecraft` (TCP, limits apply to new connections), `none` (known clients and lockdown only).

Ports listed in `[whitelist] bypass_ports` skip every check, which also means they get no protection. Use it only for things like a monitoring port.

**Web servers.** To stop slowloris-style attacks, turn on `[conntrack] enable_connection_tracking` and set `conn_limit_per_source`.

**Behind a tunnel.** If NetDeflect also runs on the game server behind a tunnel, set its `network_interface` to the tunnel interface (for example `wg0` or `gre1`).

---

<a id="reflection"></a>
## 🪞 Reflection and amplification attacks

In a reflection attack, the attacker sends requests to thousands of public servers (DNS, NTP, memcached, SSDP, CLDAP and many more) with your address as the sender, and those servers flood you with replies.

NetDeflect drops the reflected traffic by its pattern (for example "UDP from port 123") straight away, so the attack stops reaching your services no matter how many reflectors are involved. It also blocks every reflector it sees for `block_timeout` seconds, because a large attack spreads across so many servers that each one is only a tiny share of the traffic. Blocks are added in batches, so tens of thousands of reflectors cost one firewall update per round.

**Only genuine amplification is matched, never the port alone.** A reflection signature matches only an oversized response (and, for game protocols, the connectionless response marker), so a FiveM, Source or other game server's normal traffic on those ports is never treated as an attack. The size floor is `[advanced_mitigation] reflection_min_length` (64 bytes by default); a packet smaller than it is never matched as reflection. NTP, DNS, memcached and the other vectors each have their own floor matching their real amplified response size.

Settings: `block_reflectors`, `reflector_block_percent` (0 blocks every reflector), `reflector_min_packets`, `max_reflector_blocks` and `reflection_min_length` in `[advanced_mitigation]`. Your resolvers and whitelisted addresses are never blocked, and DNS replies from your own resolvers are never dropped.

---

<a id="large-links"></a>
## 📡 Large links: sFlow, NetFlow and 10G/100G

On a 10G, 40G or 100G link you do not sniff every packet in userspace, and you do not want your mitigation sitting inline where a failure takes the whole link down. NetDeflect handles this the way carrier networks do: the router or switch samples traffic in hardware and exports it as sFlow or NetFlow, NetDeflect reads that telemetry out of band, and mitigation is sent upstream over BGP. If NetDeflect stops, the router keeps forwarding and the link stays up, so there is nothing to fail closed.

**What is supported**

- **sFlow v5** (recommended for rate accuracy). Each sampled packet header is decoded through the same classifier used for live capture, then scaled back up by the exporter's sampling rate. sFlow carries the rate in every sample, so packets-per-second and bandwidth are accurate in real time.
- **NetFlow v5, NetFlow v9 and IPFIX.** Flow records are decoded and scaled by the sampling rate. The rate is the traffic the records arriving in a window account for, divided by the window: over time that is unbiased whatever your exporter's active and inactive timeouts are, though with a few long flows a single window is noisy. v9/IPFIX templates are learned automatically (per exporter and source id, and bounded in memory).

**How to turn it on**

```ini
[capture]
capture_method = sflow        ; or netflow

[flow]
listen_host = 0.0.0.0
listen_port =                 ; blank = 6343 for sFlow, 2055 for NetFlow
agents = 203.0.113.1          ; optional: only accept flow from your router(s)
sampling_rate = 2000          ; your router's "1 in N" rate (used when the
                              ; exporter does not state its own)

[firewall]
firewall_system = bgp         ; out-of-band: no local rules, mitigate upstream

[escalation]
bgp_enabled = True            ; announce attacker prefixes to your upstream
bgp_mode = exabgp             ; or hook, with your own script
```

Then point your router or switch at this host's address and `listen_port`.

**What it does during an attack.** NetDeflect classifies the sampled traffic exactly as it would live packets: it recognises the vector, identifies the real reflectors or botnet sources, and asks your upstream to drop those prefixes over BGP (and/or hands them to an external firewall or scrubbing API). Because the block happens upstream, it works even when the attack is larger than your own link. Spoofed-source floods, where there is no real address to block, are reported with the vector and volume so you can trigger a destination blackhole or a scrubbing redirect; set `uplink_capacity_mbps` to have NetDeflect announce the target automatically once the pipe is full.

**Accuracy and false positives.** The detection is the same shape-based, spoof-safe logic used everywhere else in NetDeflect: a reflection vector is matched by its oversized, marker-bearing response, never by a port number, so legitimate traffic on busy service ports is not swept up. sFlow gives the most accurate real-time rates; NetFlow and IPFIX are excellent for the source and vector picture that drives upstream blocking, and their rates are smoothed over the exporter's flow timers.

**Tuning for heavy baselines.** Raise `[triggers] pps_threshold` and `mbps_threshold` to sit above your normal peak, use the per-protocol triggers for a vector that hides inside a large baseline, and raise the kernel's UDP receive buffer (`net.core.rmem_max`) if a very busy exporter ever shows gaps. The collector's own cost depends on `packet_count`, not on how big the attack is.

---

<a id="all-commands"></a>
## 🛠️ All commands

| Command | What it does |
|---|---|
| `sudo python3 netdeflect.py` | Run NetDeflect in the foreground |
| `--setup` | Guided setup that writes settings.ini |
| `--selftest` | Check dependencies, settings and firewall support |
| `--test-webhook` | Send a sample alert to your configured webhooks |
| `--dry-run` | Detect and report, block nothing |
| `--once` | Run one check and exit |
| `--block 1.2.3.4 [--for SECONDS]` | Block an address (`--for 0` lasts until NetDeflect stops) |
| `--block-net 1.2.3.0/24` | Block a range |
| `--unblock 1.2.3.4` | Remove a block |
| `--list-blocks` | List blocked addresses and ranges |
| `--stats` | Show how many packets NetDeflect has dropped |
| `--write-default-config` | Write a fresh settings.ini |
| `--install-service` | Write and enable the systemd service for this install |
| `--teardown` | Remove every firewall rule NetDeflect created |
| `--write-uninstall [PATH]` | Write a standalone uninstall_rules.sh |
| `--config PATH` | Use another settings file |
| `--log-level DEBUG` | More detailed logging |

Block commands work while the service is running and do not disturb it.

As a service (the installer's option 2, or `sudo python3 netdeflect.py --install-service`):

```bash
sudo systemctl start|stop|restart netdeflect
sudo systemctl reload netdeflect      # re-read settings.ini and methods.json
```

---

<a id="full-config"></a>
## ⚙️ Full configuration

All settings live in `settings.ini`, and every option is explained in the file itself. Settings you leave out use their defaults. The sections:

| Section | What it covers |
|---|---|
| `[general]` | Profile (`vps`, `server`, `enterprise`), update checks, tunnel detection |
| `[ip_detection]` | How the server's public IP is found |
| `[capture]` | Source (interface sniff, or sflow/netflow), sampling size and speed, saved captures, capture filter |
| `[flow]` | sFlow/NetFlow collector: listen address and port, allowed exporters, sampling rate |
| `[triggers]` | Thresholds, per-protocol triggers, detection sensitivity, hold-down time |
| `[firewall]` | Firewall type (nftables, `xdp`, ipset, blackhole, out-of-band `bgp`), XDP mode, block duration, interface scoping, watch-only mode |
| `[services]` | Your game and VPN ports, learned clients, lockdown |
| `[service:NAME]` | Optional detailed settings for one service |
| `[blocklist]` | Permanent blocks, blocklist files and URLs, port 0 / spoof / private-range drops |
| `[advanced_mitigation]` | Rate limits, reflector blocking, fragments, carpet bombing, learned patterns |
| `[conntrack]` | Optional connection tracking extras |
| `[whitelist]` | Addresses and ranges never blocked, tunnel protocols, trusted peers, bypass ports |
| `[escalation]` | Upstream BGP blackholing |
| `[metrics]` | Prometheus |
| `[notification]` | Discord, Slack/Teams, alert style and mentions, alert frequency, your own script |
| `[logging]` | Log file, level, JSON event log |
| `[display]` | Live status screen and colours |
| `[external_firewall]` | Send blocked addresses to an external API |

**Profiles** change defaults only; anything you set yourself wins.

| | vps | server | enterprise |
|---|---|---|---|
| Packets sampled per check | 5000 | 8000 | 10000 |
| Lockdown total allowance | 5000 pps | 20000 pps | 50000 pps |
| Prometheus metrics | off | off | on |
| Range blocking after | 16 addresses | 16 addresses | 8 addresses |

**More settings worth knowing:**

| Setting | Default | Notes |
|---|---|---|
| `[triggers] trigger_mode` | `MP` | `P`, `M` or both (`MP`) |
| `[advanced_mitigation] autodetect_enforce` | True | Automatically drop confident learned patterns while the attack runs |
| `[advanced_mitigation] autodetect_marker_pct` | 85 | How dominant a header field must be to count as a fingerprint |
| `[advanced_mitigation] block_autodetected_patterns` | False | Also act on lower-confidence learned patterns |
| `[notification] discord_style` | `rich` | `rich` (built-in alert) or `template` (your notification_template.json) |
| `[notification] discord_mention` | empty | Ping on attack alerts, e.g. `@here` or `<@&ROLE_ID>` |

---

<a id="signatures"></a>
## 📜 Attack signatures

Signatures live in `methods.json`. Each one describes packets by their fields; every field given must match.

```json
{ "name": "NTP Reflection", "category": "reflection", "proto": "udp", "sport": 123 }
{ "name": "TCP SYN Flood (no MSS)", "category": "syn_flood", "proto": "tcp", "tcp_flags": "SYN", "tcp_mss": "missing", "action": "drop" }
{ "name": "Qbot", "category": "botnet", "proto": "udp", "payload_hex": "51424f542d4e4554" }
```

**Match fields**

| Field | Meaning |
|---|---|
| `proto` | `udp`, `tcp`, `icmp`, `icmp6`, `gre`, `esp`, `ah` or a protocol number |
| `sport`, `dport` | Source or destination port, a number or a list |
| `tcp_flags` | Exact TCP flags, e.g. `SYN`, `SYN,ACK`, `none` |
| `tcp_flags_mask` | Which flags to compare (defaults to the six main flags, or all eight when ECE/CWR are named) |
| `tcp_mss` | MSS value, `[low, high]`, or `"missing"` |
| `tcp_window` | TCP window size |
| `tcp_reserved` | Reserved TCP bits: a value or `"nonzero"` |
| `payload_hex` | Bytes in the packet payload, in hex |
| `payload_offset` | Where those bytes start (leave out to match anywhere) |
| `payload_mask_hex` | Bit mask for the payload comparison |
| `min_len`, `max_len` | IP packet length range |
| `ttl_min`, `ttl_max` | TTL (hop limit) range |
| `tos` | DSCP/ToS byte |
| `icmp_type`, `icmp_code` | ICMP type and code |
| `src_ip`, `dst_ip` | Address or range |
| `frag` | `first`, `later` or `any` fragment |

**Options**

| Option | Meaning |
|---|---|
| `category` | Decides the response (see [How it works in detail](#how-it-works-detail)) |
| `action` | Override the response: `drop`, `ratelimit`, `block_src`, `allow`, `report` |
| `rate_pps` | Packets per second per source for `ratelimit` |
| `block_time` | Seconds a block from this signature lasts |
| `min_packets`, `min_percent` | Override detection sensitivity for this signature |
| `real_source` | `true`/`false` to override whether source addresses may be blocked |
| `log` | Log matching packets in the kernel log |
| `enabled` | `false` turns the signature off |

**Categories:** `reflection`, `amplification`, `reflection_tcp`, `dns_query`, `amplifier_abuse`, `udp_flood`, `tcp_flood`, `tcp_flag`, `proto_flood`, `fragment_flood`, `syn_flood`, `icmp_flood`, `stateful_flood`, `game_query`, `botnet`, `scanner`, `conn_flood`.

**Built in:** reflection from NTP, DNS, SSDP, SNMP, CLDAP, memcached, Chargen, QOTD, Echo, Daytime, Time, NetBIOS, Portmap, mDNS, STUN, MSSQL, WS-Discovery, TFTP, RIPv1, Sentinel, Quake 3, OpenVPN, CoAP, Ubiquiti, DVR, Jenkins, Citrix, Plex, BitTorrent, Lantronix, Digiman, Apple Remote Desktop, serialnumberd, NAT-PMP, Modbus, BACnet, SIP, ISAKMP, IPMI, XDMCP, vxWorks, Crestron, OpenAFS, BFD, SLP, Mitel TP240, DTLS, ArmA, FiveM, TeamSpeak 3, RDP, Steam, GTP, L2TP, IKEv2 and Kerberos; TCP reflection from web, BGP and mail servers; SYN, SYN-ACK, ACK, PSH-ACK, RST, RST-ACK and FIN floods; NULL, XMAS, SYN-FIN, SYN-RST, reserved-bit and ECN anomalies; ICMP, ICMPv6, GRE, ESP, AH and IPX floods; Mirai, Qbot, Legion, Chaos, RyMGang, Condi, Fodcha and other botnet payloads; TeamSpeak, Source, FiveM, Quake 3, SA-MP and Minecraft query floods; and filler payload floods.

Remove or disable signatures for services you run yourself in a way that could clash, and use `systemctl reload netdeflect` to apply changes.

**Learned patterns** are saved to `application_data/new_detected_methods.json`. Confident ones are dropped automatically during the attack they were learned in. After a restart they come back as report-only until you mark an entry `"approved": true`, or set `block_autodetected_patterns = True`.

---

<a id="integrations"></a>
## 🔌 Alerts and integrations

**Discord.** Set `webhook_url`. The default `discord_style = rich` sends the built-in alert. To use your own layout, set `discord_style = template` and edit `notification_template.json`. Placeholders: `{{attack_id}}`, `{{summary}}`, `{{action_needed}}`, `{{pps}}`, `{{mbps}}`, `{{cpu}}`, `{{status}}`, `{{dropped_pps}}`, `{{dropped_pct}}`, `{{passed_pps}}`, `{{attack_vector}}`, `{{attack_category}}`, `{{blocking_strategy}}`, `{{target_ip}}`, `{{target_port}}`, `{{top_ports}}`, `{{protocol_mix}}`, `{{unique_sources}}`, `{{source_kind}}`, `{{block_count}}`, `{{net_count}}`, `{{hostname}}`, `{{report_file}}`.

**Slack, Teams, Mattermost.** Set `text_webhook_url` to an incoming webhook.

**Your own script.** Set `notify_script`. It runs with these arguments: `action target_ip attack_vector dropped_pps attack_id`, where action is `attack` or `ended`, and receives the full report as JSON on standard input. A few lines of `curl` is enough to forward it to Discord, Telegram or a BGP tool.

**Event log.** Set `[logging] event_log` to write one JSON line per attack round.

**External firewall API.** `[external_firewall]` sends newly blocked addresses to your provider or another firewall, with bearer, basic or header authentication and a customisable request body.

---

<a id="metrics"></a>
## 📈 Metrics

With `[metrics] prometheus_enabled = True`, NetDeflect publishes:

| Metric | Meaning |
|---|---|
| `netdeflect_up` | 1 while running |
| `netdeflect_packets_per_second` | Incoming packets per second |
| `netdeflect_bytes_per_second` | Incoming bytes per second |
| `netdeflect_cpu_percent` | CPU use |
| `netdeflect_attack_active` | 1 during an attack |
| `netdeflect_attacks_total` | Attacks seen |
| `netdeflect_dropped_pps`, `netdeflect_passed_pps` | Being dropped and getting through |
| `netdeflect_blocked` | Blocked addresses and ranges |
| `netdeflect_blocked_this_round` | Blocks added in the last round |
| `netdeflect_known_clients` | Learned clients |
| `netdeflect_lockdown` | 1 while service ports are locked down |
| `netdeflect_packets_per_second_by_protocol{proto=...}` | Packets per second per protocol during an attack |

`prometheus_mode = textfile` writes `application_data/netdeflect.prom` for the node_exporter textfile collector. `prometheus_mode = http` serves `/metrics` on `prometheus_host:prometheus_port` (127.0.0.1:9209 by default).

---

<a id="bgp"></a>
## 🌐 Upstream protection with BGP

When an attack is bigger than your connection, nothing on the server can help: the connection is already full before packets arrive. If you have a BGP session with your provider, NetDeflect can ask upstream routers to drop traffic for the attacked address (remote-triggered blackhole):

```ini
[escalation]
bgp_enabled = True
bgp_mode = exabgp                      ; or hook, to run your own script
exabgp_command_pipe = /run/exabgp/exabgp.cmd
rtbh_community = 65535:666
uplink_capacity_mbps = 1000            ; escalate at 90% of this
escalate_on_saturation = True          ; or when the network card keeps dropping
```

Blackholing takes the attacked address offline upstream to protect the rest of your network, so it only happens on these conditions and is withdrawn `escalation_withdraw_after` seconds after the attack ends.

**BGP as the whole mitigation path.** Set `firewall_system = bgp` and NetDeflect installs no local rules at all: it asks your upstream to drop the attacker prefixes it identifies (and/or hands them to an external API), rather than dropping anything on this host. This is the out-of-band mode used with sFlow/NetFlow and on 10G/100G links; see [Large links](#large-links). Announcing attacker sources needs BGP FlowSpec or source-based RTBH at your provider; destination blackhole of your own address on uplink saturation works with plain RTBH.

Providers set a max-prefix limit on BGP sessions, and going over it drops the whole session. A reflection attack can involve tens of thousands of reflectors, so NetDeflect announces at most `[escalation] max_announced_prefixes` (default 500) attacker prefixes at once, heaviest first; set it below your provider's limit. The blackhole of your own address when the uplink is full is always sent. If ExaBGP is not reading its command pipe, NetDeflect logs that nothing was announced instead of waiting on the pipe.

---

<a id="files"></a>
## 📦 Files

A checkout holds only four files. Everything else is written the first time NetDeflect runs, or when you install the service, so there is nothing generated to keep in the repository.

```
netdeflect.py                 the program
methods.json                  attack signatures
install.sh                    installer
README.md                     this file
```

Written on first run, or on demand, next to the program (or in `/opt/NetDeflect` for a service install):

```
settings.ini                  your settings (written on first run, or --write-default-config / --setup)
notification_template.json    Discord alert layout (written on first run)
uninstall_rules.sh            cleanup helper (written by --install-service, or --write-uninstall)
application_data/
├── attack_analysis/          a text and JSON report per attack round
├── ips/                      addresses involved in each attack (CSV)
├── captures/                 packet captures (.pcap, readable by Wireshark)
├── known_clients.json        learned players and VPN users
├── new_detected_methods.json learned attack patterns
├── netdeflect.log            log (rotated)
└── netdeflect.prom           Prometheus metrics (if enabled)
```

The systemd unit is written to `/etc/systemd/system/netdeflect.service` by `--install-service` (the installer's service option), generated with this install's own paths.

---

<a id="advanced-faq"></a>
## ❓ Advanced FAQ

**Does it need connection tracking?** No. It is optional and off by default.

**Which firewall should I use?** nftables. It supports every feature and is installed on all current distributions. Use `xdp` (nftables plus xdp-filter) when you want banned sources dropped in the NIC driver on a busy host. iptables with ipset works for most features; the blackhole option can only block addresses; the bgp option installs no local rules and mitigates upstream (for sFlow/NetFlow and 10G/100G).

**Does it support sFlow or analysis on 10G/100G interfaces with a heavy baseline?** Yes. Set `capture_method = sflow` (or `netflow`) and point your router or switch at it; set `firewall_system = bgp` so mitigation is sent upstream. NetDeflect then runs out of band, so unlike an inline appliance it cannot fail closed and take your link down, and its shape-based detection keeps false positives low on busy service ports. See [Large links](#large-links).

**Does it use XDP or eBPF?** Optionally. With `firewall_system = xdp` it drops banned source addresses in the NIC driver with XDP (via xdp-tools' xdp-filter); nftables still does the classification and the pattern and spoofed-flood drops. See [Does NetDeflect use XDP or eBPF?](#xdp) for exactly what is and is not XDP here.

**Is Docker port forwarding covered?** Yes. NetDeflect's rules run before Docker's port forwarding, so the public ports you list in `[services]` are protected.

**How do I check nothing of mine is being learned as an attack?** Run in watch-only mode for a day and read `application_data/new_detected_methods.json`.

---

<a id="limitations"></a>
## 🚧 Limitations

- An attack that fills your connection cannot be fixed on the server; use your provider's protection, BGP blackholing, or out-of-band flow mode with `firewall_system = bgp` for that.
- NetDeflect samples traffic when a threshold is crossed, so an attack has to reach your thresholds to be acted on. Per-protocol triggers help with smaller targeted floods.
- An attack that randomises every header field and payload and matches no signature has nothing to fingerprint, so it cannot be dropped by pattern. On `[services]` ports the lockdown total cap still holds it.
- In sFlow/NetFlow mode detection is based on sampled telemetry, so it suits high-rate links and sees proportions and sources well; sFlow gives accurate real-time rates, while NetFlow/IPFIX rates are smoothed over the exporter's flow timers. Mitigation in this mode is upstream (BGP/API), not local.
- Learned clients are recognised by address. During lockdown an attacker who forges a known player's address gets that player's allowance, not more.
- Per-source rate limits remember up to `[firewall] meter_size` addresses (65535) at a time. A flood from more forged addresses than that fills the table, and sources beyond it are not rate-limited; per-source limits cannot stop a randomly spoofed flood anyway, since each forged address sends little. For game and VPN ports, `[services]` lockdown adds a total cap that does.
- Linux only. Requires root.

---

### 🏷️ Tags

**Security:** DDoS protection, DDoS mitigation, anti-DDoS, network security, attack detection, traffic analysis

**Technologies:** Python, nftables, iptables, ipset, XDP, eBPF, sFlow, NetFlow, IPFIX, BGP, FlowSpec, RTBH, ExaBGP

**Attack types:** reflection attacks, amplification attacks, SYN floods, UDP floods, ACK floods, botnet attacks, carpet bombing, pulse-wave attacks

**Games and services:** FiveM, Minecraft, CS2, Rust, Garry's Mod, SA-MP, TeamSpeak, WireGuard, OpenVPN, Pterodactyl

**Features:** real-time monitoring, automatic attack detection, pattern learning, Discord webhooks, Prometheus metrics, API integration
