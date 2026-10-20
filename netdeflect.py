#!/usr/bin/env python3
"""
NetDeflect v4 - DDoS detection and mitigation for Linux servers.
https://github.com/0vm/NetDeflect

NetDeflect watches the traffic arriving at your server. When it crosses your
thresholds it inspects a sample of the packets, works out which attack is
running, and installs firewall rules in the kernel that drop the attack while
your real traffic keeps flowing. The kernel does the dropping, so NetDeflect
itself stays light even on a one-core VPS during a large attack.

How it decides what to do
-------------------------
  * Faked sources are never blocked. Most floods use forged source addresses,
    so blocking those addresses would do nothing useful and could block an
    innocent network. They are stopped by dropping the attack pattern and by
    per-address rate limits instead.
  * Real attackers are blocked. Reflection/amplification servers and botnet
    machines really did send the traffic, so their addresses are blocked for a
    while (never your gateway, your resolvers, your SSH session, your own
    addresses or anything you whitelist).
  * Your game and VPN ports stay usable. Real players and VPN users are learned
    while things are quiet and let through first during an attack.
  * The first line of defence keeps no per-connection state, so a flood of
    fake addresses cannot exhaust it. Connection tracking is optional.

Run with --help for options, or --setup for a guided setup.
"""

import os
import re
import sys
import json
import stat
import time
import struct
import hashlib
import argparse
import logging
import logging.handlers
import signal
import shutil
import socket
import subprocess
import ipaddress
import threading
import configparser
from collections import Counter, defaultdict
from datetime import datetime

VERSION = "4.0.0"
VERSION_STRING = f"NetDeflect v{VERSION}"

# Resolve paths relative to this script so the tool works under systemd / cron
# regardless of the working directory.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATA_DIR = os.path.join(BASE_DIR, "application_data")
CAPTURE_DIR = os.path.join(DATA_DIR, "captures")
IP_DIR = os.path.join(DATA_DIR, "ips")
ANALYSIS_DIR = os.path.join(DATA_DIR, "attack_analysis")
AUTODETECT_FILE = os.path.join(DATA_DIR, "new_detected_methods.json")
STATE_FILE = os.path.join(DATA_DIR, "state.json")
METRICS_FILE = os.path.join(DATA_DIR, "netdeflect.prom")

SETTINGS_FILE = os.path.join(BASE_DIR, "settings.ini")
METHODS_FILE = os.path.join(BASE_DIR, "methods.json")
TEMPLATE_FILE = os.path.join(BASE_DIR, "notification_template.json")

log = logging.getLogger("netdeflect")


# --------------------------------------------------------------------------- #
#  Protocol helpers
# --------------------------------------------------------------------------- #

PROTO_NAMES = {
    "icmp": 1, "igmp": 2, "tcp": 6, "udp": 17, "gre": 47,
    "esp": 50, "ah": 51, "icmp6": 58, "icmpv6": 58, "ospf": 89,
    "sctp": 132, "ipip": 4, "ipv6": 41, "l2tp": 115,
}
PROTO_NUM_TO_NAME = {1: "icmp", 4: "ipip", 6: "tcp", 17: "udp", 41: "ipv6", 47: "gre",
                     50: "esp", 51: "ah", 58: "icmpv6", 115: "l2tp", 132: "sctp"}

# TCP flag bit values (low byte of the flags field).
TCP_FLAG_BITS = {
    "FIN": 0x01, "SYN": 0x02, "RST": 0x04, "PSH": 0x08,
    "ACK": 0x10, "URG": 0x20, "ECE": 0x40, "CWR": 0x80,
}
TCP_CORE_MASK = 0x3F  # FIN|SYN|RST|PSH|ACK|URG


def proto_to_num(value):
    """Accept 'udp', 'tcp', 6, '6', etc. and return the IP protocol number."""
    if value is None:
        return None
    if isinstance(value, int):
        return value
    v = str(value).strip().lower()
    if v in PROTO_NAMES:
        return PROTO_NAMES[v]
    if v.isdigit():
        return int(v)
    raise ValueError(f"Unknown protocol: {value!r}")


def flags_to_value(spec):
    """'SYN,ACK' -> 0x12 ; 'none'/'null' -> 0 ; None -> None."""
    if spec is None:
        return None
    s = str(spec).strip().lower()
    if s in ("none", "null", "0", ""):
        return 0
    value = 0
    for part in str(spec).split(","):
        name = part.strip().upper()
        if name not in TCP_FLAG_BITS:
            raise ValueError(f"Unknown TCP flag: {part!r}")
        value |= TCP_FLAG_BITS[name]
    return value


def default_flag_mask(flags_value):
    """If a signature names ECE/CWR we must compare the full 8 bits, otherwise a
    flag set that includes ECE/CWR could never match (the classic v2/v3 bug where
    SYN-ECN-CWR was dead). Core-6 signatures keep the 0x3F mask so ECN negotiation
    on an ordinary SYN does not spoil a plain 'SYN' match."""
    if flags_value is None:
        return None
    return 0xFF if (flags_value & 0xC0) else TCP_CORE_MASK


def parse_version(tag):
    """'v2.10.1' -> (2, 10, 1) so comparisons are numeric, not lexical."""
    nums = []
    for part in str(tag).lower().lstrip("v").split("."):
        digits = "".join(ch for ch in part if ch.isdigit())
        nums.append(int(digits) if digits else 0)
    return tuple(nums) if nums else (0,)


def _is_hex(s):
    try:
        int(s, 16)
        return len(s) % 2 == 0
    except (ValueError, TypeError):
        return False


# --------------------------------------------------------------------------- #
#  Category policy - the heart of the spoof-safe design
# --------------------------------------------------------------------------- #
#   spoofable   : True  -> source address is untrustworthy; NEVER block by IP.
#   strategy    : "filter" (pattern drop), "syn" (per-source SYN rate limit),
#                 "ratelimit" (per-source rate limit), "block_src" (block real
#                 source IPs), "conn_limit" (per-source concurrent connection cap,
#                 needs conntrack), "report" (log/alert only).
#   real_source : True when the source IP is genuinely the host sending the
#                 packets (a real reflector or a real attacker) so it CAN be
#                 blocked. False when forged.
#   needs_ct    : rule can only be enforced in the post-conntrack chain.

CATEGORY_POLICY = {
    # Reflection/amplification RESPONSES (keyed on a service source port): the
    # source is a real reflector. Pattern-drop always; optionally null-route the
    # heavy reflectors to drain the attacker pool.
    "reflection":    {"spoofable": True,  "strategy": "filter", "real_source": True},
    "amplification": {"spoofable": True,  "strategy": "filter", "real_source": True},
    # TCP reflection (unsolicited SYN-ACK/ACK/RST-ACK from a service source port).
    # The "reflectors" are legitimate web/CDN/BGP servers, so NEVER block them;
    # and only an UNSOLICITED reply is an attack, so this needs conntrack (the
    # established/related accept runs first) and drops only state NEW/invalid.
    "reflection_tcp": {"spoofable": True, "strategy": "filter", "real_source": False, "needs_ct": True},
    # Reflection/amplification TRIGGER queries arriving AT us (keyed on a service
    # dport, e.g. DNS ANY to udp/53). The source is the spoofed victim or a forged
    # address - never block it; rate-limit the request shape instead.
    "amplifier_abuse": {"spoofable": True, "strategy": "ratelimit", "real_source": False},
    "dns_query":     {"spoofable": True,  "strategy": "ratelimit", "real_source": False},
    # Spoofed-source floods: forged addresses, never IP-blocked.
    "udp_flood":     {"spoofable": True,  "strategy": "filter", "real_source": False},
    "tcp_flood":     {"spoofable": True,  "strategy": "filter", "real_source": False},
    "tcp_flag":      {"spoofable": True,  "strategy": "filter", "real_source": False},
    "stateful_flood": {"spoofable": True, "strategy": "report", "real_source": False, "needs_ct": True},
    "ack_flood":     {"spoofable": True,  "strategy": "report", "real_source": False, "needs_ct": True},
    "syn_flood":     {"spoofable": True,  "strategy": "syn",    "real_source": False},
    "icmp_flood":    {"spoofable": True,  "strategy": "ratelimit", "real_source": False},
    "proto_flood":   {"spoofable": True,  "strategy": "filter", "real_source": False},
    "fragment_flood": {"spoofable": True, "strategy": "filter", "real_source": False},
    # Connectionless UDP game queries: forged just as easily as any UDP, so
    # rate-limit the shape; do NOT block the (spoofable) source.
    "game_query":    {"spoofable": True,  "strategy": "ratelimit", "real_source": False},
    # Direct application-layer attacks where the source is the real attacker.
    "botnet":        {"spoofable": False, "strategy": "block_src", "real_source": True},
    "scanner":       {"spoofable": False, "strategy": "block_src", "real_source": True},
    "conn_flood":    {"spoofable": False, "strategy": "conn_limit", "real_source": True, "needs_ct": True},
    "unclassified":  {"spoofable": True,  "strategy": "report", "real_source": False},
}


def policy_for(category):
    return CATEGORY_POLICY.get(category, CATEGORY_POLICY["unclassified"])


# --------------------------------------------------------------------------- #
#  Signatures
# --------------------------------------------------------------------------- #
#  A packet dict (produced by the decoder or a test fixture) has keys:
#    len (L3 IP datagram length), frame_len, proto, src, dst, sport, dport,
#    flags (TCP), icmp_type, icmp_code, ttl, tos (DSCP byte), payload (bytes of
#    the first payload_cap L4 bytes), frag ('first'|'later'|None), ip_id,
#    tcp_window, tcp_mss, tcp_wscale, tcp_reserved.

class Signature:
    __slots__ = ("name", "category", "proto", "sports", "dports",
                 "flags_value", "flags_mask", "payload_bytes", "payload_offset",
                 "payload_mask", "min_len", "max_len", "ttl_min", "ttl_max",
                 "tos", "icmp_type", "icmp_code", "tcp_mss", "tcp_window",
                 "tcp_reserved", "src_net", "dst_net", "frag",
                 "action", "rate_pps", "rate_bps", "log", "enabled",
                 "block_time", "min_packets", "min_percent", "_real_override",
                 "block_contributors", "auto", "source_ips", "uid")

    _counter = 0

    def __init__(self, name, category, proto=None, sport=None, dport=None,
                 tcp_flags=None, tcp_flags_mask=None, payload_hex=None,
                 payload_offset=None, payload_mask_hex=None,
                 min_len=None, max_len=None, ttl_min=None, ttl_max=None,
                 tos=None, icmp_type=None, icmp_code=None, tcp_mss=None,
                 tcp_window=None, tcp_reserved=None, src_ip=None, dst_ip=None,
                 frag=None, action=None, rate_pps=None, rate_bps=None, log=False,
                 enabled=True, block_time=None, min_packets=None,
                 min_percent=None, real_source=None, block_contributors=None,
                 auto=False, source_ips=None):
        self.name = name
        self.category = category
        self.proto = proto_to_num(proto)
        self.sports = self._portset(sport)
        self.dports = self._portset(dport)
        self.flags_value = flags_to_value(tcp_flags)
        if tcp_flags_mask is not None:
            self.flags_mask = flags_to_value(tcp_flags_mask) if not isinstance(tcp_flags_mask, int) else tcp_flags_mask
        else:
            self.flags_mask = default_flag_mask(self.flags_value)
        if payload_hex:
            ph = str(payload_hex).lower().replace(" ", "")
            if not _is_hex(ph):
                raise ValueError(f"payload_hex {payload_hex!r} is not valid even-length hex")
            self.payload_bytes = bytes.fromhex(ph)
        else:
            self.payload_bytes = None
        self.payload_offset = int(payload_offset) if payload_offset is not None else None
        if payload_mask_hex:
            pm = str(payload_mask_hex).lower().replace(" ", "")
            if not _is_hex(pm):
                raise ValueError(f"payload_mask_hex {payload_mask_hex!r} is not valid hex")
            self.payload_mask = bytes.fromhex(pm)
        else:
            self.payload_mask = None
        self.min_len = int(min_len) if min_len is not None else None
        self.max_len = int(max_len) if max_len is not None else None
        self.ttl_min = int(ttl_min) if ttl_min is not None else None
        self.ttl_max = int(ttl_max) if ttl_max is not None else None
        self.tos = int(tos) if tos is not None else None
        self.icmp_type = int(icmp_type) if icmp_type is not None else None
        self.icmp_code = int(icmp_code) if icmp_code is not None else None
        self.tcp_mss = tcp_mss
        self.tcp_window = int(tcp_window) if tcp_window is not None else None
        self.tcp_reserved = tcp_reserved  # int value, or "nonzero"
        self.src_net = ipaddress.ip_network(src_ip, strict=False) if src_ip else None
        self.dst_net = ipaddress.ip_network(dst_ip, strict=False) if dst_ip else None
        self.frag = frag  # None | 'later' | 'first' | 'any'
        self.action = action.lower() if action else None
        self.rate_pps = int(rate_pps) if rate_pps is not None else None
        self.rate_bps = int(rate_bps) if rate_bps is not None else None
        self.log = bool(log)
        self.enabled = bool(enabled)
        self.block_time = int(block_time) if block_time is not None else None
        self.min_packets = int(min_packets) if min_packets is not None else None
        self.min_percent = float(min_percent) if min_percent is not None else None
        self._real_override = real_source
        self.block_contributors = block_contributors
        self.auto = auto
        self.source_ips = source_ips or []
        Signature._counter += 1
        self.uid = Signature._counter

    @staticmethod
    def _portset(spec):
        if spec is None:
            return None
        if isinstance(spec, (list, tuple)):
            return set(int(p) for p in spec)
        return {int(spec)}

    @staticmethod
    def _mss_match(value, spec):
        if isinstance(spec, str) and spec.lower() == "missing":
            return value is None
        if value is None:
            return False
        if isinstance(spec, (list, tuple)) and len(spec) == 2:
            return spec[0] <= value <= spec[1]
        return value == int(spec)

    @property
    def spoofable(self):
        return policy_for(self.category)["spoofable"]

    @property
    def needs_ct(self):
        return policy_for(self.category).get("needs_ct", False)

    @property
    def strategy(self):
        if self.action == "allow":
            return "allow"
        if self.action == "ratelimit":
            return "ratelimit"
        if self.action == "drop":
            return "filter"
        if self.action in ("block", "block_src"):
            return "block_src"
        if self.action == "report":
            return "report"
        return policy_for(self.category)["strategy"]

    @property
    def real_source(self):
        if self._real_override is not None:
            return bool(self._real_override)
        return policy_for(self.category).get("real_source", False)

    def matches(self, pkt):
        if self.proto is not None and pkt.get("proto") != self.proto:
            return False
        # Non-first fragments carry no usable L4 header; only proto/len/frag/src
        # fields are trustworthy. Reject any signature that needs L4 detail.
        if pkt.get("frag") == "later":
            if (self.sports or self.dports or self.flags_value is not None
                    or self.payload_bytes is not None or self.icmp_type is not None):
                return False
        if self.frag is not None:
            pf = pkt.get("frag")
            if self.frag == "any" and not pf:
                return False
            if self.frag in ("first", "later") and pf != self.frag:
                return False
        if self.sports is not None and pkt.get("sport") not in self.sports:
            return False
        if self.dports is not None and pkt.get("dport") not in self.dports:
            return False
        if self.flags_value is not None:
            flags = pkt.get("flags")
            if flags is None or (flags & self.flags_mask) != self.flags_value:
                return False
        if self.min_len is not None and pkt.get("len", 0) < self.min_len:
            return False
        if self.max_len is not None and pkt.get("len", 0) > self.max_len:
            return False
        if self.ttl_min is not None and (pkt.get("ttl") is None or pkt["ttl"] < self.ttl_min):
            return False
        if self.ttl_max is not None and (pkt.get("ttl") is None or pkt["ttl"] > self.ttl_max):
            return False
        if self.tos is not None and pkt.get("tos") != self.tos:
            return False
        if self.icmp_type is not None and pkt.get("icmp_type") != self.icmp_type:
            return False
        if self.icmp_code is not None and pkt.get("icmp_code") != self.icmp_code:
            return False
        if self.tcp_mss is not None:
            if pkt.get("proto") != 6 or not self._mss_match(pkt.get("tcp_mss"), self.tcp_mss):
                return False
        if self.tcp_window is not None and pkt.get("tcp_window") != self.tcp_window:
            return False
        if self.tcp_reserved is not None:
            rv = pkt.get("tcp_reserved")
            if rv is None:
                return False
            if self.tcp_reserved == "nonzero":
                if rv == 0:
                    return False
            elif rv != int(self.tcp_reserved):
                return False
        if self.src_net is not None and not _ip_in(pkt.get("src"), self.src_net):
            return False
        if self.dst_net is not None and not _ip_in(pkt.get("dst"), self.dst_net):
            return False
        if self.payload_bytes is not None:
            payload = pkt.get("payload") or b""
            if self.payload_offset is None:
                if self.payload_mask is not None:
                    return False  # masked match requires a fixed offset
                if payload.find(self.payload_bytes) < 0:
                    return False
            else:
                seg = payload[self.payload_offset:self.payload_offset + len(self.payload_bytes)]
                if len(seg) < len(self.payload_bytes):
                    return False
                if self.payload_mask is not None:
                    m = self.payload_mask
                    for i, b in enumerate(self.payload_bytes):
                        mb = m[i] if i < len(m) else 0xFF
                        if (seg[i] & mb) != (b & mb):
                            return False
                elif seg != self.payload_bytes:
                    return False
        return True


def _ip_in(ip, net):
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.version == net.version and addr in net


_SIG_FIELDS = ("proto", "sport", "dport", "tcp_flags", "tcp_flags_mask",
               "payload_hex", "payload_offset", "payload_mask_hex", "min_len",
               "max_len", "ttl_min", "ttl_max", "tos", "icmp_type", "icmp_code",
               "tcp_mss", "tcp_window", "tcp_reserved", "src_ip", "dst_ip",
               "frag", "action", "rate_pps", "rate_bps", "log", "block_time",
               "min_packets", "min_percent", "real_source", "block_contributors")


def _build_signature(entry):
    kw = {k: entry[k] for k in _SIG_FIELDS if k in entry}
    return Signature(name=entry["name"],
                     category=entry.get("category", "unclassified"), **kw)


def load_signatures(cfg=None):
    """Load methods.json plus any auto-detected signatures.

    cfg (optional) lets loading respect trusted_ports (disable signatures that
    would hit your own service ports) and block_autodetected_patterns (learned
    signatures are loaded report-only unless acting on them is enabled AND the
    entry is marked approved)."""
    sigs = []
    names_seen = {}
    trusted_ports = set(cfg["trusted_ports"]) if cfg else set()
    act_on_auto = bool(cfg and cfg.get("block_autodetected_patterns"))

    def _add(entry, auto=False):
        try:
            if not isinstance(entry, dict):
                raise ValueError("signature entry is not an object")
            if entry.get("enabled") is False:
                return
            sig = _build_signature(entry)
            sig.auto = auto
            # Reflection/amplification is defined by an OVERSIZED response. Apply a
            # minimum-length floor so a signature never matches a small legitimate
            # packet merely because it shares a service port (e.g. game servers).
            if cfg and sig.category in ("reflection", "amplification") and sig.min_len is None:
                sig.min_len = cfg.get("reflection_min_length", 64)
            if auto and not act_on_auto and not entry.get("approved"):
                sig.action = "report"          # learned but not yet trusted to drop
            ports = (sig.sports or set()) | (sig.dports or set())
            if trusted_ports and ports & trusted_ports:
                log.info("Disabling signature %r (hits trusted_ports %s)",
                         sig.name, sorted(ports & trusted_ports))
                return
            if sig.name in names_seen:
                names_seen[sig.name] += 1
                sig.name = f"{sig.name}#{names_seen[sig.name]}"
            else:
                names_seen[sig.name] = 0
            sigs.append(sig)
        except Exception as exc:  # noqa: BLE001 - one bad entry must not kill load
            log.warning("Skipping malformed signature %r: %s",
                        entry.get("name") if isinstance(entry, dict) else entry, exc)

    try:
        with open(METHODS_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        log.error("methods.json not found at %s", METHODS_FILE)
        return []
    except json.JSONDecodeError as exc:
        log.error("methods.json is not valid JSON: %s", exc)
        return []

    raw = data.get("signatures", []) if isinstance(data, dict) else data
    if not isinstance(raw, list):
        log.error("methods.json 'signatures' is not a list")
        return []
    builtin = 0
    for entry in raw:
        before = len(sigs)
        _add(entry, auto=False)
        builtin += len(sigs) - before

    auto_loaded = 0
    try:
        if os.path.exists(AUTODETECT_FILE):
            with open(AUTODETECT_FILE, "r", encoding="utf-8") as fh:
                auto_data = json.load(fh)
            if isinstance(auto_data, list):
                for entry in auto_data:
                    if isinstance(entry, dict):
                        entry.setdefault("category", "udp_flood")
                        # learned patterns are saved with "label" and a single
                        # "ttl"; map them to the signature fields so they reload
                        entry.setdefault("name", entry.get("label") or "Auto_learned")
                        if entry.get("ttl") is not None and entry.get("ttl_min") is None:
                            entry["ttl_min"] = entry["ttl_max"] = entry["ttl"]
                        # legacy v2 category names -> v4 categories
                        if entry.get("category") in ("valid_ip_attacks", "spoofed_ip_attacks"):
                            entry["category"] = "udp_flood"
                        before = len(sigs)
                        _add(entry, auto=True)
                        auto_loaded += len(sigs) - before
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("Could not load auto-detected methods: %s", exc)

    log.info("Loaded %d signatures (%d built-in, %d auto-detected)",
             len(sigs), builtin, auto_loaded)
    return sigs


# --------------------------------------------------------------------------- #
#  Configuration
# --------------------------------------------------------------------------- #

CONFIG_TEMPLATE = """\
; NetDeflect settings
; Most people only need to set: [notification] webhook_url and [services] ports.
; Everything else has a sensible default. Run `python3 netdeflect.py --setup`
; for a guided setup, or `--selftest` to check your system.

[general]
; Default tuning for your machine. Any setting you change below still wins.
;   vps        - small VPS / single game server / VPN box (default, lightest)
;   server     - busier dedicated server
;   enterprise - fleets and datacentres (enables metrics)
profile = vps
; Check GitHub for new NetDeflect releases (logs a notice, never auto-updates).
check_for_updates = True
; Find your GRE / IPIP / WireGuard tunnels automatically: their remote endpoints
; are trusted and the tunnel protocol is never treated as a flood.
auto_detect_tunnels = True

[ip_detection]
; How NetDeflect learns this server's public IP so it never blocks itself.
; Options: opendns, google_dns, ipify, icanhazip, local, none
ip_method = opendns

[capture]
; Network interface to protect. "auto" uses the interface of your default route.
; Several interfaces: eth0, eth1
network_interface = auto
; Where traffic is read from:
;   afpacket - built-in sniffer on the interface above (recommended, 1-10G)
;   tcpdump  - same, via tcpdump
;   tshark   - same, via tshark
;   sflow    - listen for sFlow v5 from your router/switch (for 10G/40G/100G)
;   netflow  - listen for NetFlow v5/v9 or IPFIX from your router/switch
; sflow and netflow are out-of-band: NetDeflect never sits in the traffic path,
; so it cannot fail closed. Mitigation is sent upstream (set firewall_system = bgp).
; Configure the exporter and collector in the [flow] section below.
capture_method = afpacket
; Most packets examined per check. NetDeflect's CPU use depends on this number,
; not on how big the attack is.
packet_count = 5000
; Most seconds spent sampling per check.
capture_seconds = 5
; Look at 1 in N sampled packets. Raise on very fast links to save CPU.
sampling_rate = 1
; Bytes read from each packet for analysis.
snaplen = 128
; Bytes of each packet kept in saved capture files (0 = whole packet).
pcap_snaplen = 0
; Bytes of packet payload compared against signatures (0 turns payload checks off).
payload_cap = 64
; Save the packets of each attack as a .pcap file for later analysis.
save_captures = True
; Optional capture filter in tcpdump syntax, e.g. "not port 22". Usually empty.
filter_arguments =

[flow]
; Only used when capture_method is sflow or netflow. Point your router or switch
; here (it exports the samples; NetDeflect analyses them and mitigates upstream).
; Address to listen on (0.0.0.0 = all interfaces).
listen_host = 0.0.0.0
; UDP port the exporter sends to. Leave empty to use the usual port for the method
; (6343 for sFlow, 2055 for NetFlow/IPFIX). Set it if your router uses another.
listen_port =
; Only accept flow packets from these exporter addresses (comma separated). Leave
; empty to accept from any source on the port above (fine on a trusted mgmt VLAN).
agents =
; Scale counts back up by this ratio when the exporter does not state its own
; sampling rate (sFlow and NetFlow v5 carry it; many NetFlow v9/IPFIX exporters
; do not). Set it to the "1 in N" rate configured on your router, e.g. 2000.
sampling_rate = 1

[triggers]
; When to start mitigating.
;   P  = packets per second over pps_threshold
;   M  = megabytes per second over mbps_threshold
;   MP = both over their thresholds (a threshold of 0 is ignored)
trigger_mode = MP
pps_threshold = 15000
; In megaBYTES per second (240 Mbit/s = 30).
mbps_threshold = 30
; Optional per-protocol triggers in packets per second (0 = off). Useful when one
; protocol floods while total traffic still looks normal.
threshold_tcp_pps = 0
threshold_udp_pps = 0
threshold_icmp_pps = 0
; Optional per-protocol triggers in megabytes per second (0 = off).
threshold_tcp_mbps = 0
threshold_udp_mbps = 0
threshold_icmp_mbps = 0
; How often (seconds) to sample per protocol while not under attack. Only used
; when a per-protocol trigger is set.
per_protocol_check_interval = 10
; A signature counts as part of the attack when it matches at least this
; percentage of sampled packets...
detection_percent = 3
; ...and at least this many packets.
detection_min_packets = 100
; Seconds to wait between mitigation rounds during an attack.
mitigation_pause = 20
; Seconds of normal traffic before an attack is declared over. Protection stays
; up during this time, so on/off "pulse" attacks are not let through in the gaps.
holddown_seconds = 120

[firewall]
; How blocks are enforced:
;   nftables  - recommended, fastest and most complete
;   xdp       - nftables PLUS xdp-filter: banned source addresses are also dropped
;               in the NIC driver (XDP) before they reach the kernel. Needs the
;               xdp-tools package and an XDP-capable interface; if either is
;               missing it runs exactly as nftables. See xdp_mode below.
;   ipset     - iptables with ipset
;   iptables  - plain iptables (slow with many blocks)
;   blackhole - null routes only (blocks addresses, cannot drop attack patterns)
;   bgp       - out-of-band: no local rules, ask upstream to drop the attacker
;               prefixes over BGP (and/or an external API). The right choice with
;               sflow/netflow and on 10G/100G links, where you cannot drop in
;               userspace. Configure the session in [escalation].
firewall_system = nftables
; Only used when firewall_system = xdp. How xdp-filter attaches to the interface:
;   native - in the driver, fastest (needs driver support; most 10G+ NICs have it)
;   skb    - generic, works on any driver (slower). Used automatically if native
;            is not available.
;   hw     - offloaded to the NIC hardware (needs specific NICs)
xdp_mode = native
; Most source addresses held in the XDP drop map (the rest stay on nftables).
; xdp-filter's map holds at most 10000 per address family.
xdp_max_entries = 4000
; Most new addresses pushed into XDP per round (each one is an xdp-filter call;
; nftables already drops the rest, and they move into XDP over the next rounds).
xdp_adds_per_round = 512
; How long an automatic block lasts, in seconds (0 = until NetDeflect stops).
block_timeout = 3600
; Only filter traffic arriving on the interface(s) above. Leave True so Docker
; bridges, VPN links and other internal traffic are never touched.
scope_rules_to_interfaces = True
; Drop all incoming IPv6 (only if you do not use IPv6 at all).
block_all_ipv6 = False
; Set False to watch and report without blocking anything (same as --dry-run).
; A good way to run the first day on a new server.
enable_ban = True
dry_run = False

[services]
; Your own public ports: game servers, VPN servers, tunnel endpoints.
; Floods aimed at these ports are mitigated. Format: port/protocol, separated by
; commas. Protocol is udp, tcp or both. Ranges are allowed. Add :wireguard or
; :openvpn to also drop any packet that is not valid for that protocol.
; Example: ports = 7777/udp, 27015-27016/both, 25565/tcp, 51820/udp:wireguard
ports =
; Packets per second allowed from any single address to these ports in normal
; operation (0 = no limit). Game clients send well under 200 per second.
rate_per_source = 0
; Learn which addresses are your real players or VPN users while things are
; quiet, so they keep working first during an attack.
learn_clients = True
; Seconds between learning passes, and how long a learned client is remembered.
learn_interval = 120
client_memory_hours = 72
; During an attack, addresses that are not learned clients are limited to this
; many packets per second each...
lockdown_rate_per_source = 50
; ...and to this many packets per second in total, so a flood from thousands of
; fake addresses cannot swamp the port. Learned clients are not affected.
lockdown_total_rate = 5000
; Turn lockdown off entirely with False.
lockdown_during_attack = True
; Only lock down if at least this many clients have been learned (otherwise new
; players would all share the small budget above).
lockdown_min_clients = 5

[blocklist]
; Addresses or ranges blocked permanently while NetDeflect runs.
; Manage them live with --block, --block-net, --unblock and --list-blocks.
block_ips =
block_nets =
; A file of addresses or ranges to block, one per line (# for comments).
blocklist_file =
; Blocklist URLs fetched automatically, e.g. https://www.spamhaus.org/drop/drop.txt
blocklist_urls =
; Seconds between blocklist downloads (86400 = daily).
blocklist_refresh = 86400
; Drop packets to or from port 0, which never appear in real traffic.
drop_port0 = True
; Drop packets that arrive from outside claiming to come from this server.
land_drop = True
; Drop packets from private or reserved address ranges arriving on the public
; interface. Leave False if this server receives private-range traffic on it.
bogon_filter = False

[advanced_mitigation]
; Enable SYN cookies so SYN floods cannot exhaust connection slots.
enable_syn_cookies = True
; New TCP connections per second allowed from one address during a SYN flood.
syn_rate_limit = 200
; ICMP (ping) packets per second allowed from one address during an ICMP flood.
icmp_rate_limit = 50
; Packets per second allowed from one address for flooded query types (DNS ANY,
; game server queries) during an attack.
query_rate_limit = 100
; Always-on overall limits in packets per second (0 = off). Only set these if you
; know your normal traffic, since they apply to everyone.
blanket_udp_pps = 0
blanket_icmp_pps = 0
; Block the servers used in a reflection/amplification attack. The attack
; traffic itself is always dropped; this also blocks every reflector seen.
block_reflectors = True
; Smallest response, in bytes, that counts as amplification. Reflection signatures
; never match a packet below this size, so legitimate small packets from a service
; port (for example a FiveM or Source game server's own traffic) are never treated
; as an attack. Only genuine oversized amplification replies are caught.
reflection_min_length = 64
; Only block reflectors sending at least this percentage of sampled traffic.
; 0 blocks every reflector seen (recommended: big attacks use thousands of them).
reflector_block_percent = 0
; A reflector must be seen in at least this many sampled packets.
reflector_min_packets = 1
; Most reflectors blocked per round (protects memory on huge attacks).
max_reflector_blocks = 20000
; Never drop DNS replies from the resolvers this server uses.
exempt_resolvers = True
; IP fragments: off, ratelimit or drop. Real traffic is sometimes fragmented,
; so ratelimit is the safe choice.
fragment_action = ratelimit
fragment_rate_pps = 1000
; Alert when one of your /24 ranges is flooded even if no single address is
; over the threshold ("carpet bombing"). Packets per second, 0 = off.
carpet_pps_threshold = 0
; Block the sources of a flood when it comes from only a few addresses that
; each look genuine. Off by default because flood sources are usually faked.
block_flood_contributors = False
flood_contributor_percent = 30
flood_contributor_max_sources = 8
flood_contributor_block_time = 600
; Learn new attack patterns from attacks no signature recognises, by fingerprinting
; the whole packet (source port, TTL, TCP window, DSCP, TCP flags, length, payload)
; and building the most specific drop rule that still covers the attack.
enable_pattern_detection = True
; Automatically enforce a HIGH-confidence learned pattern (two or more matching
; header fields, or a shared payload) as a spoof-safe pattern drop. This is what
; stops an attack no built-in signature knows. Turn it off to only log them.
autodetect_enforce = True
; Also enforce LOWER-confidence learned patterns (one marker). Off by default;
; these are saved for you to review instead.
block_autodetected_patterns = False
; A header field counts as part of the fingerprint when this percentage of the
; attack's packets share it. Higher = stricter (fewer, more certain patterns).
autodetect_marker_pct = 85
; Guards so normal traffic is never learned as an attack:
autodetect_min_sources = 5
autodetect_min_percent = 15
autodetect_heavy_source_percent = 20
autodetect_block_time = 900
; Last resort for unrecognised attacks: block the biggest senders.
enable_fallback_blocking = False
contributor_threshold = 30
; Block a whole /24 (IPv4) or /64 (IPv6) once this many of its addresses are blocked.
subnet_aggregate_count = 16
; Number of saved capture files to keep (0 = keep all).
max_pcap_files = 20

[conntrack]
; Connection tracking is off by default. NetDeflect does not need it, and under a
; flood of fake addresses it costs CPU and memory. Turn it on only for the extra
; protections below.
enable_connection_tracking = False
; Drop packets that do not belong to any connection (ACK/RST/FIN floods).
drop_invalid = False
; Drop reflection replies this server never asked for.
reflection_ct_drop = False
; Most simultaneous TCP connections from one address to the ports below
; (stops slowloris-style attacks). 0 = off.
conn_limit_per_source = 0
conn_limit_ports = 80, 443
; Warn when the connection table is this full (percent).
conntrack_warn_percent = 80

[whitelist]
; Addresses that are never blocked. Your gateway, this server, your SSH session
; and the DNS resolvers you use are protected automatically.
trusted_ips = 8.8.8.8, 8.8.4.4, 1.1.1.1, 1.0.0.1, 9.9.9.9
; Address ranges that are never blocked, e.g. your office or monitoring.
trusted_networks =
; Never block private address ranges (192.168.x.x, 10.x.x.x and so on).
protect_private_ranges = True
; Never block the DNS resolvers listed in /etc/resolv.conf.
protect_resolvers = True
; Tunnel protocols you use, so they are never treated as a flood: gre, esp, ah, ipip.
protocols_in_use =
; Addresses or ranges whose traffic skips all checks: other servers you run,
; tunnel endpoints, admin machines.
trusted_peers =
; Ports whose traffic skips ALL checks. This leaves them unprotected, so use
; [services] for game and VPN ports instead. Only for things like monitoring.
bypass_ports =

[escalation]
; Ask your upstream network to drop traffic using BGP. This is the only fix once
; your connection itself is full, and it is the mitigation path for the "bgp"
; firewall backend (where attacker prefixes are announced for your upstream to
; drop, which needs BGP FlowSpec or source-based RTBH). Needs a BGP session with
; your provider. Off by default. Set this True when firewall_system = bgp.
bgp_enabled = False
; exabgp - write commands to an ExaBGP pipe.  hook - run a script you provide.
bgp_mode = exabgp
exabgp_command_pipe = /run/exabgp/exabgp.cmd
escalation_hook_script =
; BGP community your provider uses for blackholing.
rtbh_community = 65535:666
rtbh_next_hop =
; Your connection speed in Mbit/s. Escalate when traffic reaches 90% of it.
; 0 = never escalate on traffic volume.
uplink_capacity_mbps = 0
; Also escalate when the network card itself starts dropping packets for this
; many rounds in a row.
escalate_on_saturation = False
saturation_rounds = 3
; Prefix length announced (32 = just the attacked address).
announce_prefix_len = 32
; Most attacker prefixes announced upstream at once (firewall_system = bgp).
; Providers set a max-prefix limit on the session, and going over it drops the
; whole session, so keep this below that limit. The blackhole of your own
; address when the uplink is full is always sent. 0 = no limit.
max_announced_prefixes = 500
; Seconds after the attack ends before the announcement is withdrawn.
escalation_withdraw_after = 300
; What to do about carpet bombing: alert, or rtbh (announce the whole range).
carpet_action = alert

[metrics]
; Prometheus metrics. textfile writes application_data/netdeflect.prom for the
; node_exporter textfile collector; http serves /metrics on the address below.
prometheus_enabled = False
prometheus_mode = textfile
prometheus_host = 127.0.0.1
prometheus_port = 9209

[notification]
; Discord webhook for attack alerts. Leave as is to turn Discord alerts off.
webhook_url = https://discord.com/api/webhooks/CHANGE-ME
; How Discord alerts look:
;   rich     - built-in embed, coloured by result (green mitigated, amber partial,
;              red not yet stopped), with a plain-English summary, what is being
;              dropped, target ports, sources, learned patterns and any action
;              you need to take (recommended)
;   template - your own notification_template.json with {{placeholders}}
discord_style = rich
; Optional ping with each attack alert, e.g. @here, @everyone or a role as <@&ROLE_ID>.
; The "attack ended" summary never pings.
discord_mention =
; Plain text webhook for Slack, Microsoft Teams or Mattermost (optional).
text_webhook_url =
; Send a summary when an attack ends.
notify_on_end = True
; Send an alert every mitigation round (False = only when an attack starts,
; when new attack types appear, and when it ends).
notify_every_round = False
; Script to run on every attack. It receives the attack details as JSON on
; standard input (a few lines of curl forwards it to Discord, Telegram or a BGP
; tool). Arguments: action target_ip attack_vector dropped_pps attack_id.
notify_script =
; json sends the full report on standard input; args passes values as arguments.
notify_format = json
notify_script_timeout = 10

[logging]
; Log file (rotated automatically). Leave empty to log to the screen only.
log_file = application_data/netdeflect.log
; DEBUG, INFO, WARNING or ERROR
log_level = INFO
; Write one JSON line per attack to this file, for SIEM tools. Empty = off.
event_log =
; Attack reports and address lists to keep (oldest are removed first). 0 = keep all.
max_report_files = 1000

[display]
; Live status screen: auto (on when run in a terminal), on, off.
live_dashboard = auto
; Coloured output: auto, always, never.
colour = auto
; Seconds between status updates.
stats_interval = 2

[external_firewall]
; Send blocked addresses to an outside firewall or provider API.
enable_api_integration = False
api_endpoint = https://api.example.com/firewall/block
; none, bearer, basic or header
auth_method = bearer
auth_token = your_api_token_here
auth_username =
auth_password =
additional_headers = {"Content-Type": "application/json"}
request_method = POST
; all = one request, batch = groups of max_ips_per_batch, single = one per address
sending_mode = all
max_ips_per_batch = 100
; {{IP_LIST}}, {{IP_CSV}}, {{IP}}, {{TIMESTAMP}} and {{SOURCE}} are filled in.
request_body_template = {"source": "NetDeflect", "timestamp": "{{TIMESTAMP}}", "ips": {{IP_LIST}}}
request_timeout = 10
"""


# Profile defaults: applied only to keys the operator did NOT set.
PROFILES = {
    "vps": {},
    "server": {
        ("capture", "packet_count"): "8000",
        ("services", "lockdown_total_rate"): "20000",
    },
    "enterprise": {
        ("metrics", "prometheus_enabled"): "True",
        ("capture", "packet_count"): "10000",
        ("advanced_mitigation", "subnet_aggregate_count"): "8",
        ("services", "lockdown_total_rate"): "50000",
    },
}


class ConfigError(Exception):
    """settings.ini could not be loaded; the message lists every problem."""


def write_default_config(path=SETTINGS_FILE):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(CONFIG_TEMPLATE)


def parse_ip_list(text):
    """Split on commas/whitespace and keep valid IPs or CIDRs."""
    out = []
    for token in str(text or "").replace(",", " ").split():
        try:
            ipaddress.ip_network(token, strict=False)
            out.append(token)
        except ValueError:
            log.warning("Ignoring invalid IP/CIDR entry: %r", token)
    return out


def _parse_ports(text):
    out = set()
    for token in str(text or "").replace(",", " ").split():
        token = token.strip().split("/")[0]
        if "-" in token:
            a, _, b = token.partition("-")
            if a.isdigit() and b.isdigit() and 0 < int(a) <= int(b) <= 65535:
                out.update(range(int(a), int(b) + 1))
                continue
        if token.isdigit() and 0 < int(token) <= 65535:
            out.add(int(token))
        elif token:
            log.warning("Ignoring invalid port entry: %r", token)
    return out


def _parse_csv(text):
    return [t.strip() for t in str(text or "").replace(",", " ").split() if t.strip()]


# Service presets: defaults for well-known kinds of service port.
SERVICE_PRESETS = {
    # Ordinary game server: per-source cap from config, lockdown on.
    "game":      {"known_rate_pps": 2000},
    # WireGuard: only the four WireGuard message types are valid; a VPN user can
    # legitimately send a lot, so no per-source cap and no cap on known clients.
    "wireguard": {"proto": "udp", "min_len": 60, "known_rate_pps": 0, "rate_pps": 0},
    # OpenVPN (UDP): only valid opcodes; no per-source cap for the same reason.
    "openvpn":   {"proto": "udp", "known_rate_pps": 0, "rate_pps": 0},
    # Minecraft Java and other TCP games: limits apply to new connections (SYNs).
    "minecraft": {"proto": "tcp", "known_rate_pps": 0},
    # Listed only: learned clients and lockdown, nothing else.
    "none":      {"rate_pps": 0, "known_rate_pps": 0},
}


def _parse_services(text, default_rate):
    """'7777/udp, 27015-27016/both, 51820/udp:wireguard' -> list of services."""
    services = []
    for token in str(text or "").replace(",", " ").split():
        spec, _, preset = token.partition(":")
        preset = (preset or "game").lower()
        if preset not in SERVICE_PRESETS:
            raise ValueError(f"unknown service preset {preset!r} in {token!r} "
                             f"(use {', '.join(SERVICE_PRESETS)})")
        portpart, _, proto = spec.partition("/")
        proto = (proto or "both").lower()
        if proto not in ("udp", "tcp", "both"):
            raise ValueError(f"bad protocol {proto!r} in {token!r} (use udp, tcp or both)")
        ports = _parse_ports(portpart)
        if not ports:
            raise ValueError(f"bad port in {token!r}")
        p = SERVICE_PRESETS[preset]
        services.append({
            "name": ("p%d" % min(ports)) + ("_" + preset if preset != "game" else ""),
            "ports": ports, "proto": p.get("proto", proto), "preset": preset,
            "rate_pps": p.get("rate_pps", default_rate), "min_len": p.get("min_len"),
            "max_len": p.get("max_len"), "lockdown": True,
            "known_rate_pps": p.get("known_rate_pps", 0)})
    return services


def load_config(path=SETTINGS_FILE):
    if not os.path.exists(path):
        write_default_config(path)
        print(f"Created {os.path.basename(path)} with default settings. Set your "
              f"Discord webhook and game/VPN ports in it (or run --setup), then start again.")
        sys.exit(0)

    parser = configparser.ConfigParser(interpolation=None)
    try:
        if not parser.read(path, encoding="utf-8"):
            raise ConfigError(f"Could not read {path}")
    except configparser.Error as exc:
        raise ConfigError(f"{os.path.basename(path)} has a formatting problem: {exc}") from exc

    profile = parser.get("general", "profile", fallback="vps").strip().lower()
    if profile not in PROFILES:
        log.warning("Unknown profile %r; using 'vps'", profile)
        profile = "vps"
    for (sec, key), val in PROFILES[profile].items():
        if not parser.has_section(sec):
            parser.add_section(sec)
        if not parser.has_option(sec, key):
            parser.set(sec, key, val)

    cfg = {"profile": profile}
    errors = []

    def req(section, key, cast=str, default=None):
        try:
            raw = parser.get(section, key)
        except (configparser.NoSectionError, configparser.NoOptionError):
            return default
        try:
            if cast is bool:
                return parser.getboolean(section, key)
            return cast(raw)
        except ValueError:
            errors.append(f"[{section}] {key} = {raw!r} should be a "
                          f"{'True/False value' if cast is bool else 'number' if cast in (int, float) else cast.__name__}")
            return default

    cfg["check_for_updates"] = req("general", "check_for_updates", bool, True)
    cfg["auto_detect_tunnels"] = req("general", "auto_detect_tunnels", bool, True)
    cfg["ip_method"] = req("ip_detection", "ip_method", str, "opendns")

    cfg["interfaces"] = _parse_csv(req("capture", "network_interface", str, "auto")) or ["auto"]
    cfg["network_interface"] = cfg["interfaces"][0]
    cfg["capture_method"] = req("capture", "capture_method", str, "afpacket").lower()
    cfg["packet_count"] = max(10, req("capture", "packet_count", int, 5000))
    cfg["capture_seconds"] = max(1, req("capture", "capture_seconds", int, 5))
    cfg["sampling_rate"] = max(1, req("capture", "sampling_rate", int, 1))
    cfg["snaplen"] = req("capture", "snaplen", int, 128)
    cfg["pcap_snaplen"] = req("capture", "pcap_snaplen", int, 0)
    cfg["payload_cap"] = req("capture", "payload_cap", int, 64)
    cfg["save_captures"] = req("capture", "save_captures", bool, True)
    cfg["filter_arguments"] = req("capture", "filter_arguments", str, "")
    cfg["inbound_only"] = req("capture", "inbound_only", bool, True)

    cfg["flow_listen_host"] = (req("flow", "listen_host", str, "0.0.0.0") or "0.0.0.0").strip()
    default_flow_port = 6343 if cfg["capture_method"] == "sflow" else 2055
    port_raw = (req("flow", "listen_port", str, "") or "").strip()
    try:
        cfg["flow_listen_port"] = int(port_raw) if port_raw else default_flow_port
    except ValueError:
        errors.append(f"[flow] listen_port = {port_raw!r} should be a number")
        cfg["flow_listen_port"] = default_flow_port
    cfg["flow_agents"] = _parse_csv(req("flow", "agents", str, ""))
    cfg["flow_sampling_rate"] = max(1, req("flow", "sampling_rate", int, 1))

    cfg["trigger_mode"] = req("triggers", "trigger_mode", str, "MP").upper()
    cfg["pps_threshold"] = req("triggers", "pps_threshold", int, 15000)
    cfg["mbps_threshold"] = req("triggers", "mbps_threshold", float, 30.0)
    for proto in ("tcp", "udp", "icmp"):
        cfg[f"threshold_{proto}_pps"] = req("triggers", f"threshold_{proto}_pps", int, 0)
        cfg[f"threshold_{proto}_mbps"] = req("triggers", f"threshold_{proto}_mbps", float, 0.0)
    cfg["per_protocol_check_interval"] = max(1, req("triggers", "per_protocol_check_interval", int, 10))
    cfg["detection_percent"] = req("triggers", "detection_percent", float, 3.0)
    dmp = req("triggers", "detection_min_packets", int, None)
    if dmp is None:
        legacy = req("triggers", "detection_threshold", int, None)
        if legacy is not None:
            log.warning("detection_threshold is a v2 setting; treating it as "
                        "detection_min_packets = %d", legacy)
            dmp = legacy
    cfg["detection_min_packets"] = dmp if dmp is not None else 100
    cfg["mitigation_pause"] = max(0, req("triggers", "mitigation_pause", int, 20))
    cfg["holddown_seconds"] = max(0, req("triggers", "holddown_seconds", int, 120))

    fw = req("firewall", "firewall_system", str, "nftables").lower()
    if fw == "ufw":
        log.warning("The ufw backend is not supported; using 'ipset' instead "
                    "(it works alongside ufw).")
        fw = "ipset"
    cfg["firewall_system"] = fw
    cfg["nft_hook"] = req("firewall", "nft_hook", str, "prerouting").lower()
    cfg["xdp_mode"] = req("firewall", "xdp_mode", str, "native").lower()
    cfg["xdp_max_entries"] = max(0, req("firewall", "xdp_max_entries", int, 4000))
    if cfg["xdp_max_entries"] > 10000:
        log.warning("xdp_max_entries = %d is above xdp-filter's map size; using 10000",
                    cfg["xdp_max_entries"])
        cfg["xdp_max_entries"] = 10000
    cfg["xdp_adds_per_round"] = max(1, req("firewall", "xdp_adds_per_round", int, 512))
    cfg["block_timeout"] = req("firewall", "block_timeout", int, 3600)
    cfg["scope_rules_to_interfaces"] = req("firewall", "scope_rules_to_interfaces", bool, True)
    cfg["meter_size"] = req("firewall", "meter_size", int, 65535)
    cfg["block_all_ipv6"] = req("firewall", "block_all_ipv6", bool, False)
    cfg["enable_ban"] = req("firewall", "enable_ban", bool, True)
    cfg["dry_run"] = req("firewall", "dry_run", bool, False) or not cfg["enable_ban"]

    sv = "services"
    cfg["service_rate_per_source"] = req(sv, "rate_per_source", int, 0)
    svc_text = req(sv, "ports", str, "")
    legacy_tp = req("whitelist", "trusted_ports", str, "")
    if legacy_tp.strip():
        log.warning("[whitelist] trusted_ports is now [services] ports: these ports "
                    "are protected rather than skipped. Use [whitelist] bypass_ports "
                    "if you really want a port left unprotected.")
        svc_text = (svc_text + ", " + legacy_tp) if svc_text.strip() else legacy_tp
    try:
        cfg["services"] = _parse_services(svc_text, cfg["service_rate_per_source"])
    except ValueError as exc:
        errors.append(f"[services] ports: {exc}")
        cfg["services"] = []
    # Optional detailed sections: [service:name]
    for section in parser.sections():
        if not section.lower().startswith("service:"):
            continue
        name = "".join(ch for ch in section.split(":", 1)[1] if ch.isalnum() or ch == "_")[:20] or "svc"
        try:
            preset = parser.get(section, "preset", fallback="game").lower()
            base = SERVICE_PRESETS.get(preset)
            if base is None:
                raise ValueError(f"unknown preset {preset!r}")
            ports = _parse_ports(parser.get(section, "ports", fallback=""))
            if not ports:
                raise ValueError("needs ports =")
            proto = parser.get(section, "protocol", fallback=base.get("proto", "both")).lower()
            if proto not in ("udp", "tcp", "both"):
                raise ValueError(f"bad protocol {proto!r}")

            def _i(key, dflt):
                v = parser.get(section, key, fallback=None)
                return int(v) if v not in (None, "") else dflt
            cfg["services"].append({
                "name": name, "ports": ports, "proto": proto, "preset": preset,
                "rate_pps": _i("rate_per_source", base.get("rate_pps", cfg["service_rate_per_source"])),
                "min_len": _i("min_length", base.get("min_len")),
                "max_len": _i("max_length", base.get("max_len")),
                "lockdown": parser.getboolean(section, "lockdown", fallback=True),
                "known_rate_pps": _i("known_client_rate", base.get("known_rate_pps", 0))})
        except ValueError as exc:
            errors.append(f"[{section}] {exc}")
    cfg["service_ports"] = set()
    for svc in cfg["services"]:
        cfg["service_ports"] |= svc["ports"]
    cfg["learn_clients_setting"] = req(sv, "learn_clients", bool, True)
    cfg["learn_known_clients"] = cfg["learn_clients_setting"] and bool(cfg["services"])
    cfg["tunnel_peers"] = []   # filled in by tunnel auto-detection
    cfg["learn_interval"] = max(30, req(sv, "learn_interval", int, 120))
    cfg["client_memory_hours"] = max(1, req(sv, "client_memory_hours", int, 72))
    cfg["lockdown_rate_pps"] = req(sv, "lockdown_rate_per_source", int, 50)
    cfg["lockdown_total_pps"] = req(sv, "lockdown_total_rate", int, 5000)
    cfg["lockdown_during_attack"] = req(sv, "lockdown_during_attack", bool, True)
    cfg["lockdown_min_clients"] = req(sv, "lockdown_min_clients", int, 5)
    cfg["notrack_service_ports"] = req(sv, "notrack", bool, False)

    cfg["block_ips"] = parse_ip_list(req("blocklist", "block_ips", str, ""))
    cfg["block_nets"] = parse_ip_list(req("blocklist", "block_nets", str, ""))
    cfg["blocklist_file"] = req("blocklist", "blocklist_file", str, "")
    cfg["blocklist_urls"] = _parse_csv(req("blocklist", "blocklist_urls", str, ""))
    cfg["blocklist_refresh"] = max(300, req("blocklist", "blocklist_refresh", int, 86400))
    cfg["blocklist_fail_open"] = req("blocklist", "blocklist_fail_open", bool, True)
    cfg["drop_port0"] = req("blocklist", "drop_port0", bool, True)
    cfg["land_drop"] = req("blocklist", "land_drop", bool, True)
    cfg["bogon_filter"] = req("blocklist", "bogon_filter", bool, False)

    am = "advanced_mitigation"
    cfg["enable_syn_cookies"] = req(am, "enable_syn_cookies", bool, True)
    cfg["syn_rate_limit"] = req(am, "syn_rate_limit", int, 200)
    cfg["icmp_rate_limit"] = req(am, "icmp_rate_limit", int, 50)
    cfg["query_rate_limit"] = req(am, "query_rate_limit", int, 100)
    cfg["blanket_udp_pps"] = req(am, "blanket_udp_pps", int, 0)
    cfg["blanket_icmp_pps"] = req(am, "blanket_icmp_pps", int, 0)
    cfg["reflection_min_length"] = req(am, "reflection_min_length", int, 64)
    cfg["block_reflectors"] = req(am, "block_reflectors", bool, True)
    cfg["reflector_block_percent"] = req(am, "reflector_block_percent", float, 0.0)
    cfg["reflector_min_packets"] = max(1, req(am, "reflector_min_packets", int, 1))
    cfg["max_reflector_blocks"] = req(am, "max_reflector_blocks", int, 20000)
    cfg["exempt_resolvers"] = req(am, "exempt_resolvers", bool, True)
    cfg["fragment_action"] = req(am, "fragment_action", str, "ratelimit").lower()
    cfg["fragment_rate_pps"] = req(am, "fragment_rate_pps", int, 1000)
    cfg["carpet_pps_threshold"] = req(am, "carpet_pps_threshold", int, 0)
    bfc = req(am, "block_flood_contributors", bool, None)
    if bfc is None:
        legacy = req(am, "block_other_attack_contributors", bool, None)
        if legacy is not None:
            log.warning("block_other_attack_contributors is a v2 setting; treating "
                        "it as block_flood_contributors")
            bfc = legacy
    cfg["block_flood_contributors"] = bool(bfc)
    cfg["flood_contributor_percent"] = req(am, "flood_contributor_percent", float, 30.0)
    cfg["flood_contributor_max_sources"] = req(am, "flood_contributor_max_sources", int, 8)
    cfg["flood_contributor_block_time"] = req(am, "flood_contributor_block_time", int, 600)
    cfg["enable_pattern_detection"] = req(am, "enable_pattern_detection", bool, True)
    cfg["block_autodetected_patterns"] = req(am, "block_autodetected_patterns", bool, False)
    cfg["autodetect_enforce"] = req(am, "autodetect_enforce", bool, True)
    cfg["autodetect_marker_pct"] = req(am, "autodetect_marker_pct", float, 85.0)
    cfg["autodetect_min_sources"] = req(am, "autodetect_min_sources", int, 5)
    cfg["autodetect_min_percent"] = req(am, "autodetect_min_percent", float, 15.0)
    cfg["autodetect_heavy_source_percent"] = req(am, "autodetect_heavy_source_percent", float, 20.0)
    cfg["autodetect_block_time"] = req(am, "autodetect_block_time", int, 900)
    cfg["enable_fallback_blocking"] = req(am, "enable_fallback_blocking", bool, False)
    cfg["contributor_threshold"] = req(am, "contributor_threshold", float, 30.0)
    cfg["subnet_aggregate_count"] = req(am, "subnet_aggregate_count", int, 16)
    cfg["max_pcap_files"] = req(am, "max_pcap_files", int, 20)

    ct = "conntrack"
    cfg["enable_connection_tracking"] = req(ct, "enable_connection_tracking", bool, False)
    cfg["drop_invalid"] = req(ct, "drop_invalid", bool, False) and cfg["enable_connection_tracking"]
    cfg["reflection_ct_drop"] = req(ct, "reflection_ct_drop", bool, False) and cfg["enable_connection_tracking"]
    cfg["conn_limit_per_source"] = req(ct, "conn_limit_per_source", int, 0) if cfg["enable_connection_tracking"] else 0
    cfg["conn_limit_ports"] = _parse_ports(req(ct, "conn_limit_ports", str, "80, 443"))
    cfg["conntrack_warn_percent"] = req(ct, "conntrack_warn_percent", float, 80.0)

    cfg["trusted_ips"] = parse_ip_list(req("whitelist", "trusted_ips", str, ""))
    cfg["trusted_networks"] = parse_ip_list(req("whitelist", "trusted_networks", str, ""))
    cfg["protect_private_ranges"] = req("whitelist", "protect_private_ranges", bool, True)
    cfg["protect_resolvers"] = req("whitelist", "protect_resolvers", bool, True)
    cfg["protocols_in_use"] = [p.lower() for p in _parse_csv(req("whitelist", "protocols_in_use", str, ""))]
    cfg["trusted_peers"] = parse_ip_list(req("whitelist", "trusted_peers", str, ""))
    cfg["bypass_ports"] = _parse_ports(req("whitelist", "bypass_ports", str, ""))
    cfg["trusted_ports"] = set()   # legacy key, folded into services above

    es = "escalation"
    cfg["bgp_enabled"] = req(es, "bgp_enabled", bool, False)
    cfg["bgp_mode"] = req(es, "bgp_mode", str, "exabgp").lower()
    cfg["exabgp_command_pipe"] = req(es, "exabgp_command_pipe", str, "/run/exabgp/exabgp.cmd")
    cfg["escalation_hook_script"] = req(es, "escalation_hook_script", str, "")
    cfg["rtbh_community"] = req(es, "rtbh_community", str, "65535:666")
    cfg["rtbh_next_hop"] = req(es, "rtbh_next_hop", str, "")
    cfg["uplink_capacity_mbps"] = req(es, "uplink_capacity_mbps", float, 0.0)
    cfg["escalate_on_saturation"] = req(es, "escalate_on_saturation", bool, False)
    cfg["saturation_rounds"] = max(1, req(es, "saturation_rounds", int, 3))
    cfg["announce_prefix_len"] = req(es, "announce_prefix_len", int, 32)
    cfg["max_announced_prefixes"] = max(0, req(es, "max_announced_prefixes", int, 500))
    cfg["escalation_withdraw_after"] = req(es, "escalation_withdraw_after", int, 300)
    cfg["carpet_action"] = req(es, "carpet_action", str, "alert").lower()

    cfg["prometheus_enabled"] = req("metrics", "prometheus_enabled", bool, False)
    cfg["prometheus_mode"] = req("metrics", "prometheus_mode", str, "textfile").lower()
    cfg["prometheus_host"] = req("metrics", "prometheus_host", str, "127.0.0.1")
    cfg["prometheus_port"] = req("metrics", "prometheus_port", int, 9209)

    nt = "notification"
    cfg["webhook_url"] = req(nt, "webhook_url", str, "")
    cfg["text_webhook_url"] = req(nt, "text_webhook_url", str, "")
    cfg["discord_style"] = (req(nt, "discord_style", str, "rich") or "rich").strip().lower()
    cfg["discord_mention"] = (req(nt, "discord_mention", str, "") or "").strip()
    cfg["notify_on_end"] = req(nt, "notify_on_end", bool, True)
    cfg["notify_every_round"] = req(nt, "notify_every_round", bool, False)
    cfg["notify_script"] = req(nt, "notify_script", str, "")
    cfg["notify_format"] = req(nt, "notify_format", str, "json").lower()
    cfg["notify_script_timeout"] = req(nt, "notify_script_timeout", int, 10)

    cfg["log_file"] = req("logging", "log_file", str, "")
    cfg["log_level"] = req("logging", "log_level", str, "INFO")
    cfg["event_log"] = req("logging", "event_log", str, "")
    cfg["max_report_files"] = req("logging", "max_report_files", int, 1000)

    cfg["live_dashboard"] = req("display", "live_dashboard", str, "auto").lower()
    cfg["colour"] = req("display", "colour", str, "auto").lower()
    cfg["stats_interval"] = max(1, req("display", "stats_interval", int, 2))

    ext = "external_firewall"
    cfg["enable_api_integration"] = req(ext, "enable_api_integration", bool, False)
    cfg["api_endpoint"] = req(ext, "api_endpoint", str, "")
    cfg["auth_method"] = req(ext, "auth_method", str, "none").lower()
    cfg["auth_token"] = req(ext, "auth_token", str, "")
    cfg["auth_username"] = req(ext, "auth_username", str, "")
    cfg["auth_password"] = req(ext, "auth_password", str, "")
    cfg["additional_headers"] = req(ext, "additional_headers", str, "{}")
    cfg["request_method"] = req(ext, "request_method", str, "POST")
    cfg["sending_mode"] = req(ext, "sending_mode", str, "all")
    cfg["max_ips_per_batch"] = max(1, req(ext, "max_ips_per_batch", int, 100))
    cfg["request_body_template"] = req(ext, "request_body_template", str, "")
    cfg["request_timeout"] = req(ext, "request_timeout", int, 10)

    if cfg["trigger_mode"] not in ("P", "M", "MP"):
        errors.append(f"[triggers] trigger_mode must be P, M or MP (got {cfg['trigger_mode']!r})")
    if cfg["trigger_mode"] == "P" and cfg["pps_threshold"] <= 0:
        errors.append("[triggers] trigger_mode P needs pps_threshold above 0")
    if cfg["trigger_mode"] == "M" and cfg["mbps_threshold"] <= 0:
        errors.append("[triggers] trigger_mode M needs mbps_threshold above 0")
    if cfg["firewall_system"] not in ("nftables", "ipset", "iptables", "blackhole", "bgp", "xdp"):
        errors.append(f"[firewall] firewall_system must be nftables, xdp, ipset, iptables, "
                      f"blackhole or bgp (got {cfg['firewall_system']!r})")
    if cfg["xdp_mode"] not in ("native", "skb", "hw"):
        errors.append(f"[firewall] xdp_mode must be native, skb or hw (got {cfg['xdp_mode']!r})")
    if cfg["capture_method"] not in ("afpacket", "tcpdump", "tshark", "sflow", "netflow"):
        errors.append(f"[capture] capture_method must be afpacket, tcpdump, tshark, "
                      f"sflow or netflow (got {cfg['capture_method']!r})")
    flow_mode = cfg["capture_method"] in ("sflow", "netflow")
    if flow_mode and not (1 <= cfg["flow_listen_port"] <= 65535):
        errors.append(f"[flow] listen_port must be 1-65535 (got {cfg['flow_listen_port']})")
    if flow_mode and cfg["firewall_system"] != "bgp":
        log.warning("capture_method=%s reads sampled flow telemetry, so it cannot drop "
                    "packets locally: the attack traffic is not on this host. Set "
                    "firewall_system = bgp to mitigate upstream (blocks are being "
                    "detected and reported only for now).", cfg["capture_method"])
    if cfg["firewall_system"] == "bgp" and not cfg["bgp_enabled"] and not cfg["enable_api_integration"]:
        log.warning("firewall_system = bgp but neither [escalation] bgp_enabled nor "
                    "[external_firewall] enable_api_integration is on: attacks will be "
                    "detected and reported but not mitigated. Turn one of them on.")
    if cfg["block_timeout"] < 0:
        errors.append("[firewall] block_timeout must be 0 (until NetDeflect stops) or more seconds")
    if cfg["meter_size"] < 1:
        errors.append("[firewall] meter_size must be at least 1")
    for key in ("snaplen", "pcap_snaplen", "payload_cap"):
        if cfg[key] < 0:
            errors.append(f"[capture] {key} cannot be negative")
    if cfg["fragment_action"] not in ("off", "ratelimit", "drop"):
        errors.append("[advanced_mitigation] fragment_action must be off, ratelimit or drop")
    if cfg["carpet_action"] not in ("alert", "rtbh"):
        errors.append("[escalation] carpet_action must be alert or rtbh")
    if cfg["discord_style"] not in ("rich", "template"):
        errors.append(f"[notification] discord_style must be rich or template "
                      f"(got {cfg['discord_style']!r})")
    if cfg["enable_api_integration"] and not cfg["api_endpoint"]:
        errors.append("[external_firewall] enable_api_integration is True but api_endpoint is empty")
    overlap = cfg["bypass_ports"] & cfg["service_ports"]
    if overlap:
        errors.append(f"[whitelist] bypass_ports {sorted(overlap)} are also listed in "
                      f"[services] ports; a port cannot be both protected and bypassed")

    if errors:
        raise ConfigError("settings.ini needs fixing:\n  - " + "\n  - ".join(errors))
    return cfg


def resolve_interfaces(cfg):
    """Replace 'auto' with the interface of the default route."""
    if "auto" not in cfg["interfaces"]:
        return cfg
    auto = None
    try:
        out = run(["ip", "-o", "route", "show", "default"]).stdout.split()
        if "dev" in out:
            auto = out[out.index("dev") + 1]
    except Exception:  # noqa: BLE001
        pass
    if not auto:
        try:
            import psutil
            for name, st in psutil.net_if_stats().items():
                if name != "lo" and st.isup:
                    auto = name
                    break
        except Exception:  # noqa: BLE001
            pass
    auto = auto or "eth0"
    cfg["interfaces"] = [auto if i == "auto" else i for i in cfg["interfaces"]]
    cfg["interfaces"] = list(dict.fromkeys(cfg["interfaces"]))
    cfg["network_interface"] = cfg["interfaces"][0]
    log.info("Protecting interface(s): %s", ", ".join(cfg["interfaces"]))
    return cfg


# --------------------------------------------------------------------------- #
#  Host / IP context
# --------------------------------------------------------------------------- #

def run(cmd, timeout=15, check=False):
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, timeout=timeout, check=check)


def detect_public_ip(method):
    try:
        if method == "none":
            return None
        if method == "google_dns" and shutil.which("dig"):
            out = run(["dig", "TXT", "+short", "o-o.myaddr.l.google.com",
                       "@ns1.google.com"]).stdout
            return out.replace('"', "").strip() or None
        if method == "opendns" and shutil.which("dig"):
            out = run(["dig", "+short", "myip.opendns.com",
                       "@resolver1.opendns.com"]).stdout.strip()
            return out or None
        if method in ("ipify", "icanhazip"):
            import requests
            url = "https://api.ipify.org" if method == "ipify" else "https://icanhazip.com"
            return requests.get(url, timeout=5).text.strip() or None
        if method == "local":
            return socket.gethostbyname(socket.gethostname())
    except Exception as exc:  # noqa: BLE001 - best effort
        log.warning("Could not detect public IP via %s: %s", method, exc)
    return None


def local_interface_ips():
    ips = set()
    try:
        out = run(["ip", "-o", "addr", "show"]).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[2] in ("inet", "inet6"):
                ips.add(parts[3].split("/")[0])
    except Exception:  # noqa: BLE001
        pass
    return ips


def default_gateways():
    gws = set()
    try:
        out = run(["ip", "route", "show", "default"]).stdout
        for line in out.splitlines():
            toks = line.split()
            if "via" in toks:
                gws.add(toks[toks.index("via") + 1])
    except Exception:  # noqa: BLE001
        pass
    return gws


def resolver_ips():
    """DNS resolvers this server uses (systemd-resolved's real upstreams too,
    not just its 127.0.0.53 stub)."""
    ips = set()
    for path in ("/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"):
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == "nameserver":
                        ip = parts[1].split("%")[0]
                        try:
                            ipaddress.ip_address(ip)
                            ips.add(ip)
                        except ValueError:
                            pass
        except OSError:
            pass
    return ips


def ssh_peer_ip():
    conn = os.environ.get("SSH_CONNECTION", "")
    return conn.split()[0] if conn else None


# RFC bogon / martian ranges (source addresses that must not appear on a public
# interface). Used both for the "never block me" guard and the optional bogon drop.
BOGON_NETS_V4 = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16",
    "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
    "255.255.255.255/32")]
BOGON_NETS_V6 = [ipaddress.ip_network(n) for n in (
    "::1/128", "::/128", "::ffff:0:0/96", "64:ff9b:1::/48", "100::/64",
    "2001:db8::/32", "fc00::/7", "fe80::/10")]
# Ranges protect_private_ranges keeps out of blocklist feeds: the bogons plus
# multicast (traffic you subscribed to, never a source to ban).
_NON_PUBLIC_V4 = BOGON_NETS_V4 + [ipaddress.ip_network("224.0.0.0/4")]
_NON_PUBLIC_V6 = BOGON_NETS_V6 + [ipaddress.ip_network("ff00::/8")]


class WhitelistGuard:
    """Decides whether an address may be blocked."""

    def __init__(self, cfg):
        self.protect_private = cfg["protect_private_ranges"]
        self.networks = []
        self.own_ips = set()
        exact = set()
        self.own_ips |= set(local_interface_ips())
        exact |= self.own_ips
        exact |= default_gateways()
        peer = ssh_peer_ip()
        if peer:
            exact.add(peer)
        if cfg.get("protect_resolvers"):
            exact |= resolver_ips()
        pub = detect_public_ip(cfg["ip_method"])
        if pub:
            exact.add(pub)
            self.own_ips.add(pub)
            log.info("Protecting detected public IP: %s", pub)
        self.public_ip = pub

        entries = (list(cfg["trusted_ips"]) + list(cfg["trusted_networks"])
                   + list(cfg["trusted_peers"]) + [p for p, _ in cfg.get("tunnel_peers", [])]
                   + list(exact))
        for item in entries:
            try:
                self.networks.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                continue
        log.info("Whitelist: %d protected networks/addresses%s", len(self.networks),
                 ", plus private ranges" if self.protect_private else "")

    def is_protected(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
        except (ValueError, TypeError):
            return True  # unparseable -> never touch it
        if (addr.is_loopback or addr.is_multicast or addr.is_unspecified
                or addr.is_link_local or addr.is_reserved):
            return True
        if self.protect_private and addr.is_private:
            return True
        for net in self.networks:
            if addr.version == net.version and addr in net:
                return True
        return False


# --------------------------------------------------------------------------- #
#  Network statistics (inbound) and saturation signals
# --------------------------------------------------------------------------- #

def network_sample(interface):
    import psutil
    counters = psutil.net_io_counters(pernic=True)
    nic = counters.get(interface)
    if nic is None:
        return None
    return nic.packets_recv, nic.bytes_recv


def get_network_stats(interface, window=1.0):
    import psutil
    first = network_sample(interface)
    if first is None:
        time.sleep(window)
        return 0, 0.0, psutil.cpu_percent(), False
    time.sleep(window)
    second = network_sample(interface)
    cpu = psutil.cpu_percent()
    if second is None:
        return 0, 0.0, cpu, True
    pps = int((second[0] - first[0]) / window)
    mbps = round((second[1] - first[1]) / window / 1024 / 1024, 3)
    return max(pps, 0), max(mbps, 0.0), cpu, True


def get_network_stats_multi(interfaces, window=1.0):
    import psutil
    if len(interfaces) <= 1:
        iface = interfaces[0] if interfaces else "eth0"
        pps, mbps, cpu, ok = get_network_stats(iface, window)
        return pps, mbps, cpu, ok, iface
    firsts = {i: network_sample(i) for i in interfaces}
    time.sleep(window)
    cpu = psutil.cpu_percent()
    total_pps = total_mbps = 0.0
    busiest, busiest_pps = interfaces[0], -1
    ok = False
    for i in interfaces:
        f, s = firsts.get(i), network_sample(i)
        if f is None or s is None:
            continue
        ok = True
        p = (s[0] - f[0]) / window
        total_pps += p
        total_mbps += (s[1] - f[1]) / window / 1024 / 1024
        if p > busiest_pps:
            busiest, busiest_pps = i, p
    return max(int(total_pps), 0), round(max(total_mbps, 0.0), 3), cpu, ok, busiest


def _read_int(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return None


def nic_drop_counters(interfaces):
    """Sum NIC RX drops that happen BEFORE netfilter (rx_missed/rx_dropped/
    rx_fifo). A rising count means the host itself is losing packets - a
    saturation signal the firewall drop counter cannot show."""
    total = 0
    found = False
    for iface in interfaces:
        base = f"/sys/class/net/{iface}/statistics"
        for name in ("rx_missed_errors", "rx_dropped", "rx_fifo_errors"):
            v = _read_int(os.path.join(base, name))
            if v is not None:
                found = True
                total += v
    return total if found else None


def softnet_drops():
    """Column 2 (backlog drops) and 3 (time_squeeze) of /proc/net/softnet_stat."""
    try:
        drops = squeeze = 0
        with open("/proc/net/softnet_stat", encoding="utf-8") as fh:
            for line in fh:
                cols = line.split()
                if len(cols) >= 3:
                    drops += int(cols[1], 16)
                    squeeze += int(cols[2], 16)
        return drops, squeeze
    except (OSError, ValueError):
        return None, None


def conntrack_usage():
    """(count, max) of nf_conntrack, or (None, None) if conntrack is not loaded."""
    count = _read_int("/proc/sys/net/netfilter/nf_conntrack_count")
    cmax = _read_int("/proc/sys/net/netfilter/nf_conntrack_max")
    return count, cmax


# --------------------------------------------------------------------------- #
#  Packet capture + native decode
# --------------------------------------------------------------------------- #

ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_8021Q = 0x8100
ETH_P_8021AD = 0x88A8
ETH_P_ALL = 0x0003
PACKET_HOST = 0
PACKET_BROADCAST = 1
PACKET_MULTICAST = 2
PACKET_OUTGOING = 4
_IPV6_EXT = {0: None, 43: None, 44: 8, 60: None, 51: "ah", 135: None,
             139: None, 140: None}  # value: fixed length or None=(len+1)*8

# ARPHRD hardware types -> pcap linktype. 1 = Ethernet, 101 = raw IP.
_HATYPE_LINKTYPE = {
    1: 1, 772: 1,                       # Ethernet, loopback
    768: 101, 769: 101, 778: 101,       # IPIP tunnel, IP6 tunnel, GRE
    65534: 101, 519: 101, 512: 101,     # none (tun/wg), rawip, ppp
}


def decode_frame(data, linktype=1, payload_cap=64):
    """Decode a link-layer frame into a packet dict, or None. Never raises."""
    try:
        total = len(data)
        off = 0
        ethertype = None
        if linktype == 1:  # Ethernet
            if total < 14:
                return None
            ethertype = (data[12] << 8) | data[13]
            off = 14
            while ethertype in (ETH_P_8021Q, ETH_P_8021AD):
                if total < off + 4:
                    return None
                ethertype = (data[off + 2] << 8) | data[off + 3]
                off += 4
        elif linktype == 113:  # Linux cooked SLL
            if total < 16:
                return None
            ethertype = (data[14] << 8) | data[15]
            off = 16
        elif linktype in (101, 12, 14):  # raw IP (no link header)
            ethertype = None
        else:
            if total < 14:
                return None
            ethertype = (data[12] << 8) | data[13]
            off = 14

        version = (data[off] >> 4) if total > off else 0
        if ethertype == ETH_P_IP or (ethertype is None and version == 4):
            return _decode_ipv4(data, off, total, payload_cap)
        if ethertype == ETH_P_IPV6 or (ethertype is None and version == 6):
            return _decode_ipv6(data, off, total, payload_cap)
        return None
    except Exception:  # noqa: BLE001 - never let one bad frame break a cycle
        return None


def _new_pkt(proto, src, dst, ip_len, frame_len, ttl, tos, ip_id, frag):
    return {"len": ip_len, "frame_len": frame_len, "proto": proto, "src": src,
            "dst": dst, "flags": None, "sport": None, "dport": None,
            "icmp_type": None, "icmp_code": None, "ttl": ttl, "tos": tos,
            "ip_id": ip_id, "frag": frag, "payload": None, "tcp_window": None,
            "tcp_mss": None, "tcp_wscale": None, "tcp_reserved": None}


def _parse_l4(pkt, proto, data, l4off, l3_end, payload_cap):
    """Fill L4 fields. l3_end bounds the IP datagram (excludes Ethernet padding)."""
    avail = min(l3_end, len(data))
    if proto == 6 and avail >= l4off + 20:  # TCP
        pkt["sport"] = (data[l4off] << 8) | data[l4off + 1]
        pkt["dport"] = (data[l4off + 2] << 8) | data[l4off + 3]
        off12 = data[l4off + 12]
        data_off = (off12 >> 4) * 4
        # The 3 reserved bits only. The lowest bit of this nibble is the AE
        # (accurate-ECN, formerly NS) flag, which modern stacks may set.
        pkt["tcp_reserved"] = (off12 >> 1) & 0x07
        pkt["flags"] = data[l4off + 13]
        pkt["tcp_window"] = (data[l4off + 14] << 8) | data[l4off + 15]
        # Parse TCP options for MSS / window scale.
        opt = l4off + 20
        opt_end = min(l4off + data_off, avail)
        while opt < opt_end:
            kind = data[opt]
            if kind == 0:
                break
            if kind == 1:
                opt += 1
                continue
            if opt + 1 >= opt_end:
                break
            olen = data[opt + 1]
            if olen < 2 or opt + olen > opt_end:
                break
            if kind == 2 and olen == 4:
                pkt["tcp_mss"] = (data[opt + 2] << 8) | data[opt + 3]
            elif kind == 3 and olen == 3:
                pkt["tcp_wscale"] = data[opt + 2]
            opt += olen
        if payload_cap:
            p = data[l4off + data_off:min(l4off + data_off + payload_cap, avail)]
            if p:
                pkt["payload"] = bytes(p)
    elif proto == 17 and avail >= l4off + 8:  # UDP
        pkt["sport"] = (data[l4off] << 8) | data[l4off + 1]
        pkt["dport"] = (data[l4off + 2] << 8) | data[l4off + 3]
        ulen = (data[l4off + 4] << 8) | data[l4off + 5]
        # Bound payload by the UDP length field as well as the IP datagram, so
        # Ethernet padding on short frames is never read as payload.
        udp_end = min(avail, l4off + ulen) if 8 <= ulen <= avail - l4off else avail
        if payload_cap:
            p = data[l4off + 8:min(l4off + 8 + payload_cap, udp_end)]
            if p:
                pkt["payload"] = bytes(p)
    elif proto in (1, 58) and avail >= l4off + 2:  # ICMP / ICMPv6
        pkt["icmp_type"] = data[l4off]
        pkt["icmp_code"] = data[l4off + 1]
    return pkt


def _decode_ipv4(data, off, total, payload_cap):
    if total < off + 20:
        return None
    ver_ihl = data[off]
    if (ver_ihl >> 4) != 4:
        return None
    ihl = (ver_ihl & 0x0F) * 4
    if ihl < 20 or total < off + ihl:
        return None
    tos = data[off + 1]
    tot_len = (data[off + 2] << 8) | data[off + 3]
    ip_id = (data[off + 4] << 8) | data[off + 5]
    flags_frag = (data[off + 6] << 8) | data[off + 7]
    frag_off = flags_frag & 0x1FFF
    mf = bool(flags_frag & 0x2000)
    ttl = data[off + 8]
    proto = data[off + 9]
    src = f"{data[off+12]}.{data[off+13]}.{data[off+14]}.{data[off+15]}"
    dst = f"{data[off+16]}.{data[off+17]}.{data[off+18]}.{data[off+19]}"
    # L3 datagram length from the header (falls back to captured bytes if the
    # header is implausible, e.g. TSO/GRO rewrote it to 0).
    captured = total - off
    ip_len = tot_len if ihl <= tot_len <= captured else captured
    l3_end = off + ip_len
    frag = "later" if frag_off > 0 else ("first" if mf else None)
    pkt = _new_pkt(proto, src, dst, ip_len, total - off, ttl, tos, ip_id, frag)
    if frag == "later":
        return pkt  # non-first fragment: no usable L4 header
    return _parse_l4(pkt, proto, data, off + ihl, l3_end, payload_cap)


def _decode_ipv6(data, off, total, payload_cap):
    if total < off + 40:
        return None
    if (data[off] >> 4) != 6:
        return None
    tclass = ((data[off] & 0x0F) << 4) | (data[off + 1] >> 4)
    payload_len = (data[off + 4] << 8) | data[off + 5]
    nxt = data[off + 6]
    ttl = data[off + 7]  # hop limit
    src = socket.inet_ntop(socket.AF_INET6, bytes(data[off + 8:off + 24]))
    dst = socket.inet_ntop(socket.AF_INET6, bytes(data[off + 24:off + 40]))
    captured = total - off
    ip_len = (payload_len + 40) if (0 < payload_len <= captured - 0) else captured
    l3_end = off + min(ip_len, captured)
    pos = off + 40
    frag = None
    hops = 0
    while nxt in _IPV6_EXT and pos + 2 <= l3_end and hops < 32:
        if nxt == 44:  # Fragment header
            frag_off = ((data[pos + 2] << 8) | data[pos + 3]) & 0xFFF8
            mf = bool(data[pos + 3] & 0x1)
            frag = "later" if frag_off > 0 else ("first" if mf else frag)
            new_nxt = data[pos]
            pos += 8
            nxt = new_nxt
            if frag == "later":
                break
            continue
        fixed = _IPV6_EXT.get(nxt)
        hlen = fixed if fixed else (data[pos + 1] + 1) * 8
        new_nxt = data[pos]
        pos += hlen
        nxt = new_nxt
        hops += 1
    pkt = _new_pkt(nxt, src, dst, ip_len, total - off, ttl, tclass, None, frag)
    if frag == "later" or nxt in _IPV6_EXT:
        return pkt
    return _parse_l4(pkt, nxt, data, pos, l3_end, payload_cap)


# ---- native pcap read / write --------------------------------------------- #

def iter_pcap(path):
    """Yield (linktype, frame_bytes, orig_len) from a classic pcap file."""
    with open(path, "rb") as fh:
        gh = fh.read(24)
        if len(gh) < 24:
            return
        magic = gh[:4]
        if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            endian = ">"
        elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            endian = "<"
        else:
            return
        linktype = struct.unpack(endian + "I", gh[20:24])[0]
        while True:
            rh = fh.read(16)
            if len(rh) < 16:
                break
            _, _, caplen, origlen = struct.unpack(endian + "IIII", rh)
            if caplen > 262144:
                break
            frame = fh.read(caplen)
            if len(frame) < caplen:
                break
            yield linktype, frame, origlen


def write_pcap(path, frames, linktype=1):
    """frames: list of (ts_float, frame_bytes, orig_len)."""
    try:
        with open(path, "wb") as fh:
            fh.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
            for ts, frame, orig in frames:
                sec = int(ts)
                usec = int((ts - sec) * 1_000_000) % 1_000_000
                fh.write(struct.pack("<IIII", sec, usec, len(frame), orig))
                fh.write(frame)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except OSError as exc:
        log.warning("Could not write pcap %s: %s", path, exc)


# ---- BPF filter attach (afpacket) ----------------------------------------- #

def _compile_bpf(expr, iface):
    """Compile a BPF expression with tcpdump -ddd into a sock_fprog bytes blob
    and keep the ctypes buffer alive. Returns (sock_fprog_struct, keepalive)."""
    import ctypes
    if not shutil.which("tcpdump"):
        raise OSError("tcpdump needed to compile a BPF filter for afpacket")
    out = run(["tcpdump", "-i", iface, "-ddd", expr], timeout=10)
    if out.returncode != 0:
        raise OSError(f"tcpdump could not compile filter: {out.stderr.strip()[:120]}")
    nums = [int(x) for x in out.stdout.split()]
    count = nums[0]
    insns = nums[1:]
    if len(insns) != count * 4:
        raise OSError("unexpected BPF program from tcpdump")
    buf = (ctypes.c_uint64 * count)()
    for i in range(count):
        code, jt, jf, k = insns[i*4:i*4+4]
        buf[i] = (code & 0xFFFF) | ((jt & 0xFF) << 16) | ((jf & 0xFF) << 24) | ((k & 0xFFFFFFFF) << 32)
    prog = struct.pack("HxxxxxxP" if struct.calcsize("P") == 8 else "HxxP",
                       count, ctypes.addressof(buf))
    return prog, buf


# ---- AF_PACKET native sniffer --------------------------------------------- #

def afpacket_capture(iface, count, seconds, inbound_only, payload_cap,
                     snaplen=65535, pcap_bytes=0, bpf=None, sampling_rate=1,
                     include_outgoing=False):
    """Capture up to `count` frames (or until `seconds` elapse). Returns
    (packets, raw_frames) where raw_frames is a list of (ts, bytes, orig_len)."""
    if not hasattr(socket, "AF_PACKET"):
        raise OSError("AF_PACKET is only available on Linux")
    import select
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    try:
        s.bind((iface, 0))
    except OSError as exc:
        s.close()
        raise OSError(f"cannot bind AF_PACKET to {iface}: {exc}") from exc
    # Per-interface linktype from the hardware type (so raw-IP tun/wg/gre decode).
    hatype = s.getsockname()[3] if len(s.getsockname()) > 3 else 1
    linktype = _HATYPE_LINKTYPE.get(hatype, 1)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    except OSError:
        pass
    keepalive = None
    if bpf:
        try:
            prog, keepalive = _compile_bpf(bpf, iface)
            s.setsockopt(socket.SOL_SOCKET, 26, prog)  # SO_ATTACH_FILTER
        except OSError as exc:
            log.warning("BPF filter not applied (%s); capturing unfiltered", exc)
    s.setblocking(False)

    packets, raw = [], []
    seen = 0
    deadline = time.time() + seconds
    try:
        while len(packets) < count and time.time() < deadline:
            ready, _, _ = select.select([s], [], [], 0.5)
            if not ready:
                continue
            for _ in range(4096):
                try:
                    data, addr = s.recvfrom(65535)
                except (BlockingIOError, OSError):
                    break
                pkttype = addr[2] if len(addr) > 2 else PACKET_HOST
                outgoing = pkttype == PACKET_OUTGOING
                if outgoing and inbound_only and not include_outgoing:
                    continue
                if not outgoing and pkttype not in (PACKET_HOST, PACKET_BROADCAST, PACKET_MULTICAST):
                    continue
                seen += 1
                if sampling_rate > 1 and (seen % sampling_rate):
                    continue
                pkt = decode_frame(data, linktype=linktype, payload_cap=payload_cap)
                if pkt and pkt.get("proto") is not None:
                    pkt["out"] = outgoing
                    packets.append(pkt)
                    if pcap_bytes is not None:
                        kept = data if not pcap_bytes else data[:pcap_bytes]
                        raw.append((time.time(), kept, len(data)))
                    if len(packets) >= count:
                        break
    finally:
        s.close()
        del keepalive
    return packets, raw, linktype


# ---- tcpdump capture (decoded natively) ----------------------------------- #

def tcpdump_capture(cfg, capture_file):
    iface = cfg["network_interface"]
    snap = cfg["pcap_snaplen"] or cfg["snaplen"]
    base = ["tcpdump", "-i", iface, "-n", "-p", "-s", str(snap),
            "-c", str(cfg["packet_count"]), "-w", capture_file]
    if cfg["inbound_only"]:
        base[1:1] = ["-Q", "in"]
    if cfg["filter_arguments"].strip():
        import shlex
        base += shlex.split(cfg["filter_arguments"])
    try:
        proc = subprocess.Popen(base, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        log.error("tcpdump is not installed (set capture_method=afpacket)")
        return False
    try:
        proc.wait(timeout=cfg["capture_seconds"])
    except subprocess.TimeoutExpired:
        proc.send_signal(signal.SIGINT)  # flush the pcap cleanly
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
    return os.path.exists(capture_file) and os.path.getsize(capture_file) > 0


# ---- tshark parse (legacy capture_method=tshark) -------------------------- #

_TSHARK_FIELDS = ["frame.len", "ip.len", "ipv6.plen", "ip.proto", "ipv6.nxt",
                  "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "tcp.flags",
                  "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
                  "icmp.type", "icmpv6.type", "data.data", "ip.ttl", "ipv6.hlim",
                  "ip.dsfield", "icmp.code", "icmpv6.code", "tcp.window_size_value"]


def _ti(v, base=10):
    v = (v or "").strip().split(",")[0].strip()
    try:
        return int(v, base) if v else None
    except ValueError:
        return None


def parse_capture(capture_file):
    if not shutil.which("tshark"):
        log.error("tshark is not installed")
        return []
    cmd = ["tshark", "-r", capture_file, "-n", "-T", "fields",
           "-E", "separator=\t", "-E", "occurrence=f"]
    for field in _TSHARK_FIELDS:
        cmd += ["-e", field]
    # Always drop to an unprivileged account to dissect attacker bytes.
    dropper = None
    if hasattr(os, "geteuid") and os.geteuid() == 0 and shutil.which("setpriv"):
        uid = os.environ.get("SUDO_UID")
        if uid:
            gid = os.environ.get("SUDO_GID", uid)
            dropper = ["setpriv", "--reuid", uid, "--regid", gid, "--clear-groups"]
    if dropper:
        try:
            os.chmod(capture_file, 0o644)
        except OSError:
            pass
        cmd = dropper + cmd
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return []
    if proc.returncode != 0:
        log.error("tshark failed: %s", proc.stderr.strip()[:200])
        return []
    packets = []
    for line in proc.stdout.splitlines():
        cols = line.split("\t")
        if len(cols) < len(_TSHARK_FIELDS):
            cols += [""] * (len(_TSHARK_FIELDS) - len(cols))
        (flen, iplen, ip6plen, ipp, ip6n, ips, ip6s, ipd, ip6d, tf, tsp, tdp,
         usp, udp_, ic, ic6, pdata, ttl4, hlim6, dsf, iccode, ic6code, twin) = cols[:23]
        ip_len = _ti(iplen)
        if ip_len is None and ip6plen.strip():
            pl = _ti(ip6plen)
            ip_len = (pl + 40) if pl is not None else None
        payload = (pdata or "").replace(":", "").strip().lower()
        packets.append({
            "len": ip_len or _ti(flen) or 0,
            "frame_len": _ti(flen) or 0,
            "proto": _ti(ipp) if ipp.strip() else _ti(ip6n),
            "src": ips.strip() or ip6s.strip() or None,
            "dst": ipd.strip() or ip6d.strip() or None,
            "flags": _ti(tf, 16) if tf.strip() else None,
            "sport": _ti(tsp) if tsp.strip() else _ti(usp),
            "dport": _ti(tdp) if tdp.strip() else _ti(udp_),
            "icmp_type": _ti(ic) if ic.strip() else _ti(ic6),
            "icmp_code": _ti(iccode) if iccode.strip() else _ti(ic6code),
            "ttl": _ti(ttl4) if ttl4.strip() else _ti(hlim6),
            "tos": _ti(dsf, 16) if dsf.strip() else None,
            "tcp_window": _ti(twin), "tcp_mss": None, "tcp_wscale": None,
            "tcp_reserved": None, "ip_id": None, "frag": None,
            "payload": bytes.fromhex(payload) if _is_hex(payload) else None,
        })
    return packets


def capture_packets(cfg, capture_file):
    method = cfg["capture_method"]
    payload_cap = cfg["payload_cap"]
    if method == "afpacket":
        try:
            pcap_bytes = (cfg["pcap_snaplen"] if cfg["save_captures"] else None)
            packets, raw, linktype = afpacket_capture(
                cfg["network_interface"], cfg["packet_count"], cfg["capture_seconds"],
                cfg["inbound_only"], payload_cap, snaplen=cfg["snaplen"],
                pcap_bytes=pcap_bytes, bpf=cfg["filter_arguments"].strip() or None,
                sampling_rate=cfg["sampling_rate"])
            if cfg["save_captures"] and raw:
                write_pcap(capture_file, raw, linktype)
            return packets
        except OSError as exc:
            log.warning("afpacket capture failed (%s); falling back to tcpdump", exc)
            method = "tcpdump"

    if not tcpdump_capture(cfg, capture_file):
        return []
    if method == "tshark":
        return parse_capture(capture_file)
    packets = []
    rate = cfg["sampling_rate"]
    seen = 0
    for linktype, frame, _orig in iter_pcap(capture_file):
        seen += 1
        if rate > 1 and (seen % rate):
            continue
        pkt = decode_frame(frame, linktype, payload_cap)
        if pkt and pkt.get("proto") is not None:
            packets.append(pkt)
    if not cfg["save_captures"]:
        try:
            os.remove(capture_file)
        except OSError:
            pass
    return packets


# --------------------------------------------------------------------------- #
#  Flow-telemetry collector (sFlow v5, NetFlow v5/v9, IPFIX)
# --------------------------------------------------------------------------- #
#  On a 10G/100G link you do not sniff the host NIC in userspace. The router or
#  switch samples traffic in hardware and exports it as sFlow or NetFlow/IPFIX.
#  NetDeflect listens for that telemetry, decodes the sampled packet headers
#  through the SAME classifier used for live capture, scales the counts back up
#  by the sampling rate, and mitigates upstream over BGP. In this mode NetDeflect
#  is out of band: if it stops, the router keeps forwarding and the link stays up,
#  so the network never fails closed the way an inline appliance does.

def _u16(b, o):
    return (b[o] << 8) | b[o + 1]


def _u32(b, o):
    return (b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]


def _ints(b, o, n):
    v = 0
    for i in range(n):
        v = (v << 8) | b[o + i]
    return v


# sFlow sampled_header header_protocol -> pcap linktype for decode_frame.
# 1 = Ethernet, 11 = IPv4, 12 = IPv6; raw IP decodes under linktype 101.
_SFLOW_HP_LINKTYPE = {1: 1, 11: 101, 12: 101}


def decode_sflow(data, payload_cap=64):
    """Decode an sFlow v5 datagram into packet dicts. Each dict carries a
    'weight' equal to the exporter's sampling rate (one sampled packet stands for
    that many on the wire) and 'bytes' for the bandwidth estimate. Resilient:
    unknown samples and records are skipped using their own length fields."""
    out = []
    try:
        if len(data) < 28 or _u32(data, 0) != 5:
            return out
        o = 4
        addr_type = _u32(data, o); o += 4
        o += {1: 4, 2: 16}.get(addr_type, 0)          # agent address (v4, v6 or unknown)
        o += 12                                       # sub_agent_id, sequence, uptime
        nsamples = _u32(data, o); o += 4
        for _ in range(min(nsamples, 256)):
            if o + 8 > len(data):
                break
            stype = _u32(data, o) & 0xFFF
            slen = _u32(data, o + 4)
            body = o + 8
            end = body + slen
            if slen < 0 or end > len(data):
                break
            if stype in (1, 3):   # flow_sample / expanded flow_sample
                out += _sflow_flow_sample(data, body, end, stype == 3, payload_cap)
            o = end + ((-slen) % 4)        # XDR pads opaque data to 4 bytes
    except Exception:  # noqa: BLE001
        return out
    return out


def _sflow_flow_sample(b, o, end, expanded, payload_cap):
    out = []
    try:
        o += 4                                        # sequence_number
        o += 8 if expanded else 4                      # source_id (type+index, or packed)
        rate = _u32(b, o); o += 4
        o += 8                                          # sample_pool, drops
        o += 16 if expanded else 8                      # input + output interface
        nrec = _u32(b, o); o += 4
        rate = rate if rate > 0 else 1
        for _ in range(min(nrec, 64)):
            if o + 8 > end:
                break
            fmt = _u32(b, o) & 0xFFF
            flen = _u32(b, o + 4)
            rbody = o + 8
            if flen < 0 or rbody + flen > end:
                break
            if fmt == 1 and flen >= 16:   # raw packet header
                hp = _u32(b, rbody)
                frame_len = _u32(b, rbody + 4)
                stripped = _u32(b, rbody + 8)
                hdr_size = _u32(b, rbody + 12)
                hstart = rbody + 16
                hbytes = bytes(b[hstart:hstart + min(hdr_size, flen - 16)])
                lt = _SFLOW_HP_LINKTYPE.get(hp, 1)
                pkt = decode_frame(hbytes, linktype=lt, payload_cap=payload_cap)
                if pkt and pkt.get("proto") is not None:
                    pkt["weight"] = rate
                    # Signatures compare IP datagram lengths. frame_length is the
                    # whole frame (link header and usually the FCS, which is
                    # 'stripped' before the header was copied), so take those off:
                    # otherwise a small game-server reply would clear the
                    # reflection size floor in flow mode but not in live capture.
                    l2 = len(hbytes) - pkt.get("frame_len", len(hbytes))
                    ip_len = frame_len - stripped - l2 if frame_len else 0
                    if ip_len > 0:
                        pkt["len"] = ip_len
                    pkt["bytes"] = (frame_len or pkt.get("len", 0)) * rate
                    out.append(pkt)
            o = rbody + flen + ((-flen) % 4)        # XDR pads opaque data to 4 bytes
    except Exception:  # noqa: BLE001
        return out
    return out


def _flow_pkt(proto, src, dst, sport, dport, pkts, octets, flags, rate, duration_s=None):
    """Synthesize one packet dict standing for a whole flow record. weight is the
    represented packet count (used for classification shares and, summed over a
    collection window, for the aggregate rate); fpps/fbps are the flow's own rate
    while it was active, kept for reports when the exporter gave start/end times."""
    pkts = max(0, pkts)
    octets = max(0, octets)
    weight = max(1, pkts) * max(1, rate)
    bytes_total = octets * max(1, rate)
    if duration_s and duration_s > 0:
        fpps = weight / duration_s
        fbps = bytes_total / duration_s
    else:
        fpps = fbps = None
    avg = int(octets / pkts) if pkts else octets
    return {"len": avg, "frame_len": avg, "proto": proto, "src": src, "dst": dst,
            "sport": sport, "dport": dport, "flags": flags, "icmp_type": None,
            "icmp_code": None, "ttl": None, "tos": None, "ip_id": None, "frag": None,
            "payload": None, "tcp_window": None, "tcp_mss": None, "tcp_wscale": None,
            "tcp_reserved": None, "weight": weight, "bytes": bytes_total,
            "fpps": fpps, "fbps": fbps}


def decode_netflow_v5(data, rate=1):
    out = []
    try:
        if len(data) < 24 or _u16(data, 0) != 5:
            return out
        count = _u16(data, 2)
        uptime = _u32(data, 4)
        sampling = _u16(data, 22) & 0x3FFF
        rate = sampling if sampling > 1 else rate
        o = 24
        for _ in range(min(count, 1000)):
            if o + 48 > len(data):
                break
            src = ".".join(str(x) for x in data[o:o + 4])
            dst = ".".join(str(x) for x in data[o + 4:o + 8])
            dpkts = _u32(data, o + 16)
            doct = _u32(data, o + 20)
            first = _u32(data, o + 24)
            last = _u32(data, o + 28)
            sport = _u16(data, o + 32)
            dport = _u16(data, o + 34)
            flags = data[o + 37]
            proto = data[o + 38]
            dur = (last - first) / 1000.0 if last > first else None
            out.append(_flow_pkt(proto, src, dst, sport, dport, dpkts, doct,
                                 flags or None, rate, dur))
            o += 48
    except Exception:  # noqa: BLE001
        return out
    return out


# NetFlow v9 / IPFIX information-element ids we read.
_NF_FIELDS = {
    1: "octets", 2: "pkts", 4: "proto", 6: "flags", 7: "sport", 11: "dport",
    8: "src4", 12: "dst4", 27: "src6", 28: "dst6",
    21: "last_ms", 22: "first_ms",          # flowEnd/StartSysUpTime
    152: "first_ms_abs", 153: "last_ms_abs",  # flowStart/EndMilliseconds (IPFIX)
    85: "octets", 86: "pkts",               # *_total counters
    231: "octets", 232: "octets", 298: "pkts",
}


class _TemplateCache:
    """NetFlow v9 / IPFIX templates by (exporter, template id). Bounded: the
    collector may be reachable by anyone who can send it UDP (agents empty),
    and unbounded templates from spoofed exporters exhaust memory."""
    MAX_TEMPLATES = 4096
    MAX_FIELDS = 128

    def __init__(self):
        from collections import OrderedDict
        self.t = OrderedDict()   # (source_key, template_id) -> [(field_id, length), ...]

    def put(self, key, fields):
        if len(fields) > self.MAX_FIELDS:
            return
        if key in self.t:
            self.t.move_to_end(key)
        self.t[key] = fields
        while len(self.t) > self.MAX_TEMPLATES:
            self.t.popitem(last=False)


def _flow_duration(rec):
    for a, b in (("last_ms", "first_ms"), ("last_ms_abs", "first_ms_abs")):
        if rec.get(a) and rec.get(b) and rec[a] > rec[b]:
            return (rec[a] - rec[b]) / 1000.0
    return None


def decode_netflow9(data, cache, source_key, rate=1):
    """NetFlow v9 (version 9) and IPFIX (version 10): template based."""
    out = []
    try:
        ver = _u16(data, 0)
        if ver == 9:
            o = 20
            domain = _u32(data, 16) if len(data) >= 20 else 0     # source id
        elif ver == 10:
            o = 16
            domain = _u32(data, 12) if len(data) >= 16 else 0     # observation domain
        else:
            return out
        source_key = (source_key, domain)
        n = len(data)
        while o + 4 <= n:
            set_id = _u16(data, o)
            set_len = _u16(data, o + 2)
            if set_len < 4 or o + set_len > n:
                break
            body, bend = o + 4, o + set_len
            if set_id in (0, 2):          # template set
                p = body
                while p + 4 <= bend:
                    tid = _u16(data, p); fcount = _u16(data, p + 2); p += 4
                    fields = []
                    for _ in range(fcount):
                        if p + 4 > bend:
                            break
                        raw_type = _u16(data, p)
                        ftype = raw_type & 0x7FFF
                        flen = _u16(data, p + 2)
                        p += 4
                        if ver == 10 and (raw_type & 0x8000):
                            p += 4   # enterprise number follows
                        fields.append((ftype, flen))
                    if fields:
                        cache.put((source_key, tid), fields)
            elif set_id >= 256:           # data set
                fields = cache.t.get((source_key, set_id))
                if fields:
                    rlen = sum(fl for _, fl in fields)
                    if rlen and all(fl > 0 for _, fl in fields):
                        p = body
                        while p + rlen <= bend:
                            rec, q = {}, p
                            for ftype, fl in fields:
                                name = _NF_FIELDS.get(ftype)
                                if name in ("src4", "dst4") and fl == 4:
                                    rec[name] = ".".join(str(x) for x in data[q:q + 4])
                                elif name in ("src6", "dst6") and fl == 16:
                                    rec[name] = socket.inet_ntop(socket.AF_INET6, bytes(data[q:q + 16]))
                                elif name:
                                    rec[name] = _ints(data, q, fl)
                                q += fl
                            proto = rec.get("proto")
                            if proto is not None:
                                out.append(_flow_pkt(
                                    proto, rec.get("src4") or rec.get("src6"),
                                    rec.get("dst4") or rec.get("dst6"),
                                    rec.get("sport"), rec.get("dport"),
                                    rec.get("pkts", 1), rec.get("octets", 0),
                                    rec.get("flags") or None, rate, _flow_duration(rec)))
                            p += rlen
            o = bend
    except Exception:  # noqa: BLE001
        return out
    return out


class FlowCollector:
    """Listens for sFlow/NetFlow/IPFIX datagrams and, each cycle, turns the
    samples into packet dicts for the classifier plus an estimated pps and MB/s."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.method = cfg["capture_method"]
        self.sock = None
        self.cache = _TemplateCache()
        self.agents = set(cfg.get("flow_agents", []))
        self.rate = max(1, cfg.get("flow_sampling_rate", 1))
        self._ts = False

    def open(self):
        host = self.cfg["flow_listen_host"]
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.sock = socket.socket(family, socket.SOCK_DGRAM)
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except OSError:
            pass
        # A big receive buffer; SO_RCVBUFFORCE (root) is not capped by
        # net.core.rmem_max, which would otherwise drop bursts from busy exporters.
        for opt in (getattr(socket, "SO_RCVBUFFORCE", 33), socket.SO_RCVBUF):
            try:
                self.sock.setsockopt(socket.SOL_SOCKET, opt, 16 * 1024 * 1024)
                break
            except OSError:
                continue
        # Kernel arrival timestamps, so datagrams that queued while we were busy
        # mitigating are not counted as if they arrived in the current window.
        self._ts = False
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_TIMESTAMPNS", 35), 1)
            self._ts = True
        except OSError:
            pass
        self.sock.bind((host, self.cfg["flow_listen_port"]))
        self.sock.setblocking(False)
        log.info("Flow collector listening for %s on %s:%d (scaling by 1:%d where the "
                 "exporter does not say)", self.method, host,
                 self.cfg["flow_listen_port"], self.rate)

    def _decode(self, data, addr):
        if self.method == "sflow":
            return decode_sflow(data, self.cfg["payload_cap"])
        ver = _u16(data, 0) if len(data) >= 2 else 0
        if ver == 5:
            return decode_netflow_v5(data, self.rate)
        if ver in (9, 10):
            return decode_netflow9(data, self.cache, addr, self.rate)
        return []

    @staticmethod
    def _arrival(ancdata):
        for level, typ, data in ancdata:
            if level == socket.SOL_SOCKET and typ == getattr(socket, "SO_TIMESTAMPNS", 35) \
                    and len(data) >= 16:
                sec, nsec = struct.unpack("qq", data[:16])
                return sec + nsec / 1e9
        return None

    def collect(self, seconds):
        """Read flow datagrams for `seconds`. Returns (packets, pps, MB/s,
        datagrams). Rates count everything that arrived inside the window, even
        after packet_count samples have been kept for classification, and are
        divided by the time actually spent, so a busy exporter is not
        under-reported and a backlog from before the window is not over-reported."""
        import select
        packets, datagrams = [], 0
        weight = 0.0
        nbytes = 0.0
        cap = self.cfg["packet_count"]
        start = time.time()
        deadline = start + seconds
        ancsize = socket.CMSG_SPACE(16) if self._ts else 0
        while time.time() < deadline:
            timeout = max(0.0, deadline - time.time())
            r, _, _ = select.select([self.sock], [], [], min(0.5, timeout) or 0.01)
            if not r:
                continue
            for _ in range(8192):
                try:
                    if ancsize:
                        data, anc, _flags, addr = self.sock.recvmsg(65535, ancsize)
                    else:
                        data, addr = self.sock.recvfrom(65535)
                        anc = ()
                except (BlockingIOError, InterruptedError):
                    break
                except OSError:
                    break
                src = addr[0]
                if src.startswith("::ffff:"):
                    src = src[7:]           # IPv4 exporter on a dual-stack socket
                if self.agents and src not in self.agents:
                    continue
                datagrams += 1
                pk = self._decode(data, src)
                arrived = self._arrival(anc) if anc else None
                if arrived is None or arrived >= start:
                    for p in pk:
                        weight += p.get("weight", 1)
                        nbytes += p.get("bytes", 0)
                if len(packets) < cap:
                    packets += pk[:cap - len(packets)]
        elapsed = max(time.time() - start, 0.001)
        return packets, int(weight / elapsed), round(nbytes / elapsed / 1048576, 3), datagrams

    def _rates(self, packets, seconds):
        """Estimated (pps, MB/s) for samples collected over `seconds`.

        sFlow: each sample stands for `weight` packets. NetFlow/IPFIX: each flow
        record stands for the packets it counted; over a window, the records
        that arrive cover on average exactly the window's traffic whatever the
        exporter's active/inactive timeouts are, so the total is divided by the
        window. (Dividing each record by its own duration instead would
        under-count long flows by roughly active-timeout / window.)"""
        seconds = max(seconds, 0.001)
        weight = sum(p.get("weight", 1) for p in packets)
        bytes_est = sum(p.get("bytes", 0) for p in packets)
        return int(weight / seconds), round(bytes_est / seconds / 1048576, 3)

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None


# --------------------------------------------------------------------------- #
#  Classification
# --------------------------------------------------------------------------- #

class Classification:
    def __init__(self):
        self.total = 0
        self.scale = 1
        self.matched = []          # [(Signature, count, pct)]
        self.src_by_sig = {}       # sig.uid -> Counter of source IPs
        self.sig_by_uid = {}
        self.top_sources = []      # [(ip, count, pct)]
        self.top_dports = []
        self.top_protos = []
        self.proto_counts = Counter()
        self.dport_counts = Counter()
        self.near_misses = []      # [(name, count, pct)] below threshold
        self.frag_count = 0
        self.src_ttl = {}          # src -> stable ttl, or None if it varied
        self.dst_prefix_counts = Counter()  # dest /24|/64 -> count (carpet bombing)
        self.unique_sources = 0    # distinct source addresses in the sample

    @property
    def categories(self):
        return {sig.category for sig, _, _ in self.matched}

    @property
    def signature_names(self):
        return [sig.name for sig, _, _ in self.matched]


class SignatureIndex:
    """Buckets signatures so each packet checks only a few candidates."""

    def __init__(self, signatures):
        self.by_proto_sport = defaultdict(list)
        self.by_proto_dport = defaultdict(list)
        self.by_proto = defaultdict(list)
        self.payload = []
        self.wildcard = []      # proto is None and no ports/payload
        for sig in signatures:
            if sig.sports:
                for p in sig.sports:
                    self.by_proto_sport[(sig.proto, p)].append(sig)
            elif sig.dports:
                for p in sig.dports:
                    self.by_proto_dport[(sig.proto, p)].append(sig)
            elif sig.payload_bytes is not None:
                self.payload.append(sig)
            elif sig.proto is not None:
                self.by_proto[sig.proto].append(sig)
            else:
                self.wildcard.append(sig)

    def candidates(self, pkt):
        proto = pkt.get("proto")
        seen = list(self.wildcard)
        sp = pkt.get("sport")
        if sp is not None:
            seen += self.by_proto_sport.get((proto, sp), ())
        dp = pkt.get("dport")
        if dp is not None:
            seen += self.by_proto_dport.get((proto, dp), ())
        seen += self.by_proto.get(proto, ())
        if pkt.get("payload"):
            seen += self.payload
        return seen


def _trusted_packet(pkt, trusted_ports, peer_nets):
    if trusted_ports and (pkt.get("sport") in trusted_ports
                          or pkt.get("dport") in trusted_ports):
        return True
    if peer_nets:
        src = pkt.get("src")
        for net in peer_nets:
            if _ip_in(src, net):
                return True
    return False


def _peer_networks(cfg):
    nets = []
    for item in cfg.get("trusted_peers", []):
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            continue
    return nets


def classify(packets, signatures, cfg, index=None, peer_nets=None):
    result = Classification()
    result.total = sum(p.get('weight', 1) for p in packets)
    result.scale = cfg.get("sampling_rate", 1)
    if not packets:
        return result
    if index is None:
        index = SignatureIndex(signatures)
    if peer_nets is None:
        peer_nets = _peer_networks(cfg)
    # Only bypassed ports are left out of classification; your [services] ports
    # are classified like everything else so floods aimed at them are seen.
    trusted_ports = set(cfg.get("bypass_ports", set())) | set(cfg.get("trusted_ports", set()))

    sig_counts = Counter()           # uid -> count
    src_by_sig = defaultdict(Counter)
    src_counter = Counter()
    dport_counter = Counter()
    proto_counter = Counter()
    dstpfx_counter = Counter()
    src_ttls = defaultdict(set)

    for pkt in packets:
        w = pkt.get("weight", 1)
        proto = pkt.get("proto")
        if proto is not None:
            proto_counter[proto] += w
        if pkt.get("frag"):
            result.frag_count += w
        if _trusted_packet(pkt, trusted_ports, peer_nets):
            continue
        src = pkt.get("src")
        if src:
            src_counter[src] += w
            ttl = pkt.get("ttl")
            if ttl is not None and len(src_ttls[src]) < 4:
                src_ttls[src].add(ttl)
        dst = pkt.get("dst")
        if dst:
            try:
                addr = ipaddress.ip_address(dst)
                plen = 24 if addr.version == 4 else 64
                dstpfx_counter[str(ipaddress.ip_network(f"{dst}/{plen}", strict=False))] += w
            except ValueError:
                pass
        if pkt.get("dport") is not None:
            dport_counter[pkt["dport"]] += w
        for sig in index.candidates(pkt):
            if sig.matches(pkt):
                sig_counts[sig.uid] += w
                if src:
                    src_by_sig[sig.uid][src] += w

    by_uid = {s.uid: s for s in signatures}
    result.sig_by_uid = by_uid
    for uid, count in sig_counts.items():
        sig = by_uid.get(uid)
        if sig is None:
            continue
        min_pkts = max(sig.min_packets if sig.min_packets is not None else cfg["detection_min_packets"],
                       int((sig.min_percent if sig.min_percent is not None else cfg["detection_percent"])
                           / 100.0 * result.total))
        pct = 100.0 * count / result.total
        if count >= min_pkts:
            result.matched.append((sig, count, pct))
        else:
            result.near_misses.append((sig.name, count, pct))
    result.matched.sort(key=lambda x: x[1], reverse=True)
    result.near_misses.sort(key=lambda x: x[1], reverse=True)
    result.near_misses = result.near_misses[:10]
    result.src_by_sig = {uid: src_by_sig[uid] for uid in src_by_sig}

    result.top_sources = [(ip, c, 100.0 * c / result.total)
                          for ip, c in src_counter.most_common(10)]
    result.top_dports = dport_counter.most_common(5)
    result.unique_sources = len(src_counter)
    result.top_protos = proto_counter.most_common(5)
    result.proto_counts = proto_counter
    result.dport_counts = dport_counter
    result.dst_prefix_counts = dstpfx_counter
    result.src_ttl = {s: (next(iter(v)) if len(v) == 1 else None)
                      for s, v in src_ttls.items()}
    return result


# --------------------------------------------------------------------------- #
#  Firewall backends
# --------------------------------------------------------------------------- #

PROTO_NUM_TO_IPT = {1: "icmp", 6: "tcp", 17: "udp", 58: "icmpv6"}
FLAG_ORDER = ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"]
# nft spells the ECE bit 'ecn'.
_NFT_FLAG = {"FIN": "fin", "SYN": "syn", "RST": "rst", "PSH": "psh",
             "ACK": "ack", "URG": "urg", "ECE": "ecn", "CWR": "cwr"}


def flag_value_to_names(value):
    return [n for n in FLAG_ORDER if value & TCP_FLAG_BITS[n]]


def proto_name(num):
    """6 -> 'tcp', 47 -> 'gre', 111 -> '111'."""
    return PROTO_NUM_TO_NAME.get(num, str(num))


class FilterRule:
    """A pattern drop or per-source rate limit derived from a matched signature."""

    def __init__(self, sig, cfg=None):
        self.name = sig.name
        self.category = sig.category
        self.proto = sig.proto
        self.sports = sorted(sig.sports) if sig.sports else None
        self.dports = sorted(sig.dports) if sig.dports else None
        self.flags_value = sig.flags_value
        self.flags_mask = sig.flags_mask
        self.min_len = sig.min_len
        self.max_len = sig.max_len
        self.ttl_min = sig.ttl_min
        self.ttl_max = sig.ttl_max
        self.tos = sig.tos
        self.icmp_type = sig.icmp_type
        self.icmp_code = sig.icmp_code
        self.tcp_mss = sig.tcp_mss
        self.tcp_window = sig.tcp_window
        self.tcp_reserved = sig.tcp_reserved
        self.src_net = sig.src_net
        self.dst_net = sig.dst_net
        self.frag = sig.frag
        self.payload = sig.payload_bytes
        self.payload_offset = sig.payload_offset
        self.payload_mask = sig.payload_mask
        self.rate_pps = sig.rate_pps
        self.rate_bps = sig.rate_bps
        self.strategy = sig.strategy
        self.needs_ct = sig.needs_ct
        self.log = sig.log
        self.block_time = sig.block_time
        if self.strategy == "syn" and cfg:
            self.rate_pps = self.rate_pps or cfg.get("syn_rate_limit", 200)
        if self.strategy == "ratelimit" and cfg and self.rate_pps is None:
            self.rate_pps = cfg.get("icmp_rate_limit", 50) if sig.category == "icmp_flood" \
                else cfg.get("query_rate_limit", 100)
        # Per-source rate limits throttle the SOURCE, not a byte pattern: a
        # mid-payload marker (e.g. a DNS QTYPE) cannot be anchored in a kernel
        # rule, so the payload is dropped from these strategies.
        if self.strategy in ("ratelimit", "syn"):
            self.payload = None
            self.payload_mask = None

    def key(self):
        return (self.proto, tuple(self.sports or ()), tuple(self.dports or ()),
                self.flags_value, self.flags_mask, self.min_len, self.max_len,
                self.ttl_min, self.ttl_max, self.tos, self.icmp_type, self.icmp_code,
                str(self.tcp_mss), self.tcp_window, str(self.tcp_reserved),
                str(self.src_net), str(self.dst_net), self.frag, self.payload,
                self.payload_offset, self.payload_mask, self.rate_pps, self.rate_bps,
                self.strategy)

    def short_id(self):
        return hashlib.sha256(repr(self.key()).encode()).hexdigest()[:12]


class BaseFirewall:
    """Common rule bookkeeping. Subclasses translate rules for one backend.

    Safety rule: a backend that cannot express a signature field must REFUSE
    the rule (unsupported_fields) rather than install a broader one. Dropping a
    field silently turns e.g. "TCP with reserved bits set" into "all TCP"."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.dry = cfg["dry_run"]
        self.timeout = cfg["block_timeout"]
        self.active_filters = {}   # key -> (FilterRule, expiry_epoch)
        self.blocked = {}          # ip -> expiry (backends without kernel timeouts)
        self.lock = threading.RLock()
        self.lockdown = False
        self.own_ips = set()
        self.resolvers = set()
        self.static_drop4 = []
        self.static_drop6 = []
        self.signatures = []
        self._refused = set()

    def _run(self, cmd, input_text=None):
        if self.dry:
            shown = " ".join(cmd)
            if input_text:
                shown += " <<<\n" + input_text
            log.debug("[dry-run] %s", shown)
            return 0, "", ""
        try:
            p = subprocess.run(cmd, input=input_text, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, timeout=30)
            return p.returncode, p.stdout, p.stderr
        except Exception as exc:  # noqa: BLE001
            log.error("Command failed (%s): %s", " ".join(cmd[:3]), exc)
            return 1, "", str(exc)

    # -- interface ----------------------------------------------------------- #
    def apply_config(self, cfg):
        """Pick up reloaded settings that do not need the backend rebuilt."""
        self.cfg = cfg
        self.dry = cfg["dry_run"]
        self.timeout = cfg["block_timeout"]

    def pre_capture_drop_rate(self):
        """Packets per second dropped before the packet sniffer can see them
        (XDP). 0 for backends that drop inside netfilter."""
        return 0

    def setup(self):
        raise NotImplementedError

    def ensure_objects(self):
        """Make sure the table/sets/chains exist WITHOUT flushing live rules."""
        self.setup()

    def unsupported_fields(self, rule):
        return []

    def block_src(self, ip, timeout=None):
        raise NotImplementedError

    def block_net(self, net, timeout=None):
        raise NotImplementedError

    def block_many(self, ips, timeout=None):
        """Block many addresses. Backends override with a single batched call."""
        return [ip for ip in ips if self.block_src(ip, timeout)]

    def block_net_many(self, nets, timeout=None):
        return [n for n in nets if self.block_net(n, timeout)]

    def unblock_src(self, ip):
        raise NotImplementedError

    def list_blocks(self):
        return []

    def count_blocks(self):
        return len(self.list_blocks())

    def add_known_clients(self, ips, ttl):
        return 0

    def set_lockdown(self, on):
        if on != self.lockdown:
            self.lockdown = on
            log.warning("Service lockdown %s", "ENABLED (unknown sources rate-limited)"
                        if on else "lifted")
            self.sync_filters()

    def sync_filters(self):
        raise NotImplementedError

    def _install_filter(self, rule):
        self.sync_filters()
        return True

    def dropped_packets(self):
        return None

    def healthy(self):
        """False if another program has removed NetDeflect's rules."""
        return True

    def apply_filter(self, rule):
        """Register a filter. Returns True if it is (or already was) enforced."""
        with self.lock:
            bad = self.unsupported_fields(rule)
            if bad:
                if rule.key() not in self._refused:
                    self._refused.add(rule.key())
                    log.warning("Not enforcing %r on %s: cannot express %s here "
                                "(reported only; nftables supports it)",
                                rule.name, self.cfg["firewall_system"], ", ".join(bad))
                return False
            key = rule.key()
            ttl = rule.block_time if rule.block_time else self.timeout
            expiry = time.time() + ttl if ttl else float("inf")
            if key in self.active_filters:
                self.active_filters[key] = (rule, expiry)   # refresh expiry only
                return True
            self.active_filters[key] = (rule, expiry)
            ok = self._install_filter(rule)
            if not ok:
                self.active_filters.pop(key, None)
            return ok

    def cleanup_expired(self):
        with self.lock:
            now = time.time()
            before = len(self.active_filters)
            self.active_filters = {k: v for k, v in self.active_filters.items() if v[1] > now}
            if len(self.active_filters) != before:
                log.info("%d pattern rule(s) expired", before - len(self.active_filters))
                self.sync_filters()
            self._cleanup_blocked(now)

    def _cleanup_blocked(self, now):
        pass

    def teardown(self):
        pass


# ---- nftables -------------------------------------------------------------- #

_WG_TYPES = "{ 0x01000000, 0x02000000, 0x03000000, 0x04000000 }"


class NftFirewall(BaseFirewall):
    """Everything lives in `table inet netdeflect`:

      chain pre      prerouting, priority -300 (raw): runs BEFORE conntrack, so
                     nothing here creates connection state. Loopback and other
                     interfaces are accepted first, then trusted peers, ban sets,
                     always-on hygiene drops, service-port protection, and the
                     pattern / per-source rate-limit rules from detection.
      chain ctchain  prerouting, priority -150: only when connection tracking is
                     enabled. Established traffic is accepted first.

    The whole ruleset is applied as one atomic `nft -f` transaction. Ban,
    feed and known-client sets keep their elements across a rebuild."""

    supports_payload_match = True

    def __init__(self, cfg):
        super().__init__(cfg)
        self.hook = cfg.get("nft_hook", "prerouting")
        self._started = False
        self._dyn_sets = set()     # per-rule meter sets currently declared

    def _nft_script(self, text):
        return self._run(["nft", "-f", "-"], input_text=text)

    def _nft(self, *args):
        return self._run(["nft"] + list(args))

    # -- rule translation ---------------------------------------------------- #
    def unsupported_fields(self, rule):
        bad = []
        pname = PROTO_NUM_TO_IPT.get(rule.proto)
        if rule.payload is not None and pname not in ("tcp", "udp"):
            bad.append("payload on a non-TCP/UDP protocol")
        if rule.payload is not None and len(rule.payload) > 16:
            bad.append("payload longer than 16 bytes")
        if (rule.tcp_mss is not None or rule.tcp_window is not None
                or rule.tcp_reserved is not None or rule.flags_value is not None) and pname != "tcp":
            bad.append("TCP field on a non-TCP rule")
        if rule.frag == "first" and rule.proto == 58:
            bad.append("IPv6 first-fragment match")
        if rule.src_net is not None and rule.dst_net is not None \
                and rule.src_net.version != rule.dst_net.version:
            bad.append("mixed IPv4/IPv6 addresses")
        return bad

    @staticmethod
    def _families(rule):
        if rule.proto == 1:
            return ["ip"]
        if rule.proto == 58:
            return ["ip6"]
        for net in (rule.src_net, rule.dst_net):
            if net is not None:
                return ["ip" if net.version == 4 else "ip6"]
        if rule.strategy in ("ratelimit", "syn", "conn_limit"):
            return ["ip", "ip6"]
        if (rule.ttl_min is not None or rule.ttl_max is not None
                or rule.tos is not None or rule.frag is not None):
            return ["ip", "ip6"] if rule.frag != "first" else ["ip"]
        return [""]

    @staticmethod
    def _portexpr(ports):
        return ("{ " + ", ".join(map(str, ports)) + " }") if len(ports) > 1 else str(ports[0])

    def _match(self, rule, fam):
        pname = PROTO_NUM_TO_IPT.get(rule.proto)
        toks = []
        if fam in ("ip", "ip6"):
            for net, dirn in ((rule.src_net, "saddr"), (rule.dst_net, "daddr")):
                if net is not None:
                    toks += [fam, dirn, str(net)]
        if pname in ("tcp", "udp"):
            # nft needs the protocol keyword before EACH port match, so matching
            # both ends is "udp sport X udp dport Y", not "udp sport X dport Y".
            fields = []
            if rule.sports:
                fields += [pname, "sport", self._portexpr(rule.sports)]
            if rule.dports:
                fields += [pname, "dport", self._portexpr(rule.dports)]
            if fields:
                toks += fields
            else:
                toks += ["meta", "l4proto", pname]
            if rule.flags_value is not None and pname == "tcp":
                names = [_NFT_FLAG[n] for n in flag_value_to_names(rule.flags_value)]
                mnames = [_NFT_FLAG[n] for n in flag_value_to_names(rule.flags_mask)] \
                    or ["fin", "syn", "rst", "psh", "ack", "urg"]
                rhs = "|".join(names) if names else "0x0"
                toks += ["tcp", "flags", "&", "(" + "|".join(mnames) + ")", "==", rhs]
        elif pname == "icmp":
            toks += ["meta", "l4proto", "icmp"]
            if rule.icmp_type is not None:
                toks += ["icmp", "type", str(rule.icmp_type)]
            if rule.icmp_code is not None:
                toks += ["icmp", "code", str(rule.icmp_code)]
        elif pname == "icmpv6":
            toks += ["meta", "l4proto", "ipv6-icmp"]
            if rule.icmp_type is not None:
                toks += ["icmpv6", "type", str(rule.icmp_type)]
            if rule.icmp_code is not None:
                toks += ["icmpv6", "code", str(rule.icmp_code)]
        elif rule.proto is not None:
            toks += ["meta", "l4proto", str(rule.proto)]
        if pname == "tcp":
            if rule.tcp_mss is not None:
                if isinstance(rule.tcp_mss, str):
                    toks += ["tcp", "option", "maxseg", "missing"]
                elif isinstance(rule.tcp_mss, (list, tuple)):
                    toks += ["tcp", "option", "maxseg", "size", f"{rule.tcp_mss[0]}-{rule.tcp_mss[1]}"]
                else:
                    toks += ["tcp", "option", "maxseg", "size", str(rule.tcp_mss)]
            if rule.tcp_window is not None:
                toks += ["tcp", "window", str(rule.tcp_window)]
            if rule.tcp_reserved is not None:
                # the three reserved bits of TCP byte 12 (bits 100-102)
                if rule.tcp_reserved == "nonzero":
                    toks += ["@th,100,3", "!=", "0"]
                else:
                    toks += ["@th,100,3", str(int(rule.tcp_reserved))]
        if rule.min_len or rule.max_len:
            toks += ["meta", "length", f"{rule.min_len or 0}-{rule.max_len or 65535}"]
        if fam == "ip":
            if rule.ttl_min is not None or rule.ttl_max is not None:
                toks += ["ip", "ttl", f"{rule.ttl_min or 0}-{rule.ttl_max if rule.ttl_max is not None else 255}"]
            if rule.tos is not None:
                toks += ["ip", "dscp", str(rule.tos >> 2)]
            if rule.frag in ("later", "any"):
                toks += ["ip", "frag-off", "&", "0x1fff", "!=", "0"] if rule.frag == "later" \
                    else ["ip", "frag-off", "&", "0x3fff", "!=", "0"]
            elif rule.frag == "first":
                toks += ["ip", "frag-off", "&", "0x3fff", "==", "0x2000"]
        elif fam == "ip6":
            if rule.ttl_min is not None or rule.ttl_max is not None:
                toks += ["ip6", "hoplimit", f"{rule.ttl_min or 0}-{rule.ttl_max if rule.ttl_max is not None else 255}"]
            if rule.tos is not None:
                toks += ["ip6", "dscp", str(rule.tos >> 2)]
            if rule.frag in ("later", "any"):
                toks += ["exthdr", "frag", "exists"]
        if rule.payload is not None and pname in ("tcp", "udp"):
            off = 8 * (rule.payload_offset or 0)
            bits = len(rule.payload) * 8
            if rule.payload_mask is not None:
                mask = (rule.payload_mask + b"\xff" * len(rule.payload))[:len(rule.payload)]
                toks += [f"@ih,{off},{bits}", "&", "0x" + mask.hex(), "==", "0x" + rule.payload.hex()]
            else:
                toks += [f"@ih,{off},{bits}", "0x" + rule.payload.hex()]
        return " ".join(toks)

    def _saddr(self, fam):
        return "ip6 saddr" if fam == "ip6" else "ip saddr"

    def _dynset(self, prefix, rule, fam):
        return ("%s6_" if fam == "ip6" else "%s4_") % prefix + rule.short_id()

    def _verdict(self, rule, fam):
        if rule.strategy == "allow":
            return "accept"
        logst = 'log prefix "netdeflect: " ' if rule.log else ""
        if rule.strategy in ("ratelimit", "syn"):
            rate = rule.rate_pps or 50
            setname = self._dynset("rl", rule, fam)
            return (f"update @{setname} {{ {self._saddr(fam)} limit rate over "
                    f"{rate}/second burst {max(rate * 2, 2)} packets }} {logst}counter drop")
        if rule.strategy == "conn_limit":
            cap = rule.rate_pps or self.cfg.get("conn_limit_per_source", 100)
            setname = self._dynset("cl", rule, fam)
            return (f"ct state new add @{setname} {{ {self._saddr(fam)} ct count over "
                    f"{cap} }} {logst}counter drop")
        return f"{logst}counter drop"

    def _rule_strings(self, rule):
        out = []
        for fam in self._families(rule):
            match = self._match(rule, fam)
            if rule.strategy == "syn" and "tcp flags" not in match:
                match = (match + " " if match else "") + "tcp flags & (syn|ack|rst|fin) == syn"
            out.append((match + " " + self._verdict(rule, fam)).strip())
        return out

    def _rule_sets(self, rule):
        """Declared dynamic sets a rule needs (meters do not survive a re-render)."""
        sets = []
        if rule.strategy in ("ratelimit", "syn", "conn_limit"):
            prefix = "cl" if rule.strategy == "conn_limit" else "rl"
            for fam in self._families(rule):
                typ = "ipv6_addr" if fam == "ip6" else "ipv4_addr"
                flags = "dynamic" if rule.strategy == "conn_limit" else "dynamic,timeout; timeout 60s"
                sets.append((self._dynset(prefix, rule, fam), typ, flags))
        return sets

    # -- service-port protection --------------------------------------------- #
    def _service_rules(self):
        """Protection for your own game / VPN ports.

        Order per service: protocol validation, then learned clients (accepted,
        with an optional generous cap), then - only during an attack - a small
        per-source budget AND a total budget for everyone else, so a flood from
        thousands of fake addresses cannot swamp the port. Outside an attack an
        optional per-source cap applies. Traffic that passes still goes through
        the normal attack-pattern rules afterwards."""
        c = self.cfg
        out, sets = [], []
        learn = c.get("learn_known_clients")
        for svc in c.get("services", []):
            pexp = self._portexpr(sorted(svc["ports"]))
            protos = ["udp", "tcp"] if svc["proto"] == "both" else [svc["proto"]]
            sid = svc["name"]
            for proto in protos:
                if proto == "udp" and svc.get("preset") == "wireguard":
                    out.append(f"udp dport {pexp} @ih,0,32 != {_WG_TYPES} counter drop")
                if proto == "udp" and svc.get("preset") == "openvpn":
                    out.append(f"udp dport {pexp} @ih,0,5 != 1-11 counter drop")
                if svc.get("min_len") or svc.get("max_len"):
                    lo, hi = svc.get("min_len") or 0, svc.get("max_len") or 65535
                    out.append(f"{proto} dport {pexp} meta length != {lo}-{hi} counter drop")
                syn = " tcp flags & (syn|ack|rst|fin) == syn" if proto == "tcp" else ""
                lock = self.lockdown and svc.get("lockdown", True)
                for fam in ("ip", "ip6"):
                    sad = self._saddr(fam)
                    typ = "ipv6_addr" if fam == "ip6" else "ipv4_addr"
                    n = "6" if fam == "ip6" else "4"
                    if learn and svc.get("lockdown", True):
                        kr = svc.get("known_rate_pps", 0)
                        if kr:
                            sname = f"kc{n}_{sid}_{proto}"
                            sets.append((sname, typ, "dynamic,timeout; timeout 60s"))
                            out.append(f"{sad} @known{n} {proto} dport {pexp}{syn} update @{sname} "
                                       f"{{ {sad} limit rate over {kr}/second burst {kr * 2} packets }} "
                                       f"counter drop")
                        out.append(f"{sad} @known{n} {proto} dport {pexp} accept")
                    if lock:
                        lr = c.get("lockdown_rate_pps", 50)
                        if lr:
                            sname = f"lk{n}_{sid}_{proto}"
                            sets.append((sname, typ, "dynamic,timeout; timeout 60s"))
                            out.append(f"{proto} dport {pexp}{syn} update @{sname} {{ {sad} limit rate "
                                       f"over {lr}/second burst {lr * 2} packets }} counter drop")
                    elif svc.get("rate_pps"):
                        r = svc["rate_pps"]
                        sname = f"sv{n}_{sid}_{proto}"
                        sets.append((sname, typ, "dynamic,timeout; timeout 60s"))
                        out.append(f"{proto} dport {pexp}{syn} update @{sname} {{ {sad} limit rate "
                                   f"over {r}/second burst {r * 2} packets }} counter drop")
                if lock and c.get("lockdown_total_pps"):
                    t = c["lockdown_total_pps"]
                    out.append(f"{proto} dport {pexp}{syn} limit rate over {t}/second burst "
                               f"{t} packets counter drop")
        return out, sets

    # -- ruleset rendering (atomic) ------------------------------------------ #
    def _render(self):
        c = self.cfg
        L = ["add table inet netdeflect", "flush table inet netdeflect"]
        # Ban sets carry NO default timeout: every timed ban states its own, and
        # an element added without one is permanent (static / --for 0 blocks).
        for name, typ, flags in (("blk4", "ipv4_addr", "timeout"), ("blk6", "ipv6_addr", "timeout"),
                                 ("blk4net", "ipv4_addr", "interval, timeout; auto-merge"),
                                 ("blk6net", "ipv6_addr", "interval, timeout; auto-merge"),
                                 ("drop4", "ipv4_addr", "interval; auto-merge"),
                                 ("drop6", "ipv6_addr", "interval; auto-merge"),
                                 ("known4", "ipv4_addr", "timeout"), ("known6", "ipv6_addr", "timeout"),
                                 ("own4", "ipv4_addr", ""), ("own6", "ipv6_addr", ""),
                                 ("res4", "ipv4_addr", ""), ("res6", "ipv6_addr", "")):
            fl = f" flags {flags};" if flags else ""
            L.append(f"add set inet netdeflect {name} {{ type {typ};{fl} }}")
        # Rebuilt from scratch each time (not bans/known clients, which persist).
        for name in ("own4", "own6", "res4", "res6", "drop4", "drop6"):
            L.append(f"flush set inet netdeflect {name}")

        def _elems(setname, items):
            items = sorted(set(items))
            for i in range(0, len(items), 2000):
                L.append(f"add element inet netdeflect {setname} {{ {', '.join(items[i:i + 2000])} }}")

        own = {a for a in self.own_ips if not _is_loopback(a)}
        _elems("own4", [a for a in own if ":" not in a])
        _elems("own6", [a for a in own if ":" in a])
        _elems("res4", [a for a in self.resolvers if ":" not in a])
        _elems("res6", [a for a in self.resolvers if ":" in a])
        _elems("drop4", self.static_drop4)
        _elems("drop6", self.static_drop6)

        svc_rules, svc_sets = self._service_rules()
        dyn_sets = list(svc_sets)
        for rule, _exp in self.active_filters.values():
            dyn_sets += self._rule_sets(rule)
        seen = set()
        for name, typ, flags in dyn_sets:
            if name in seen:
                continue
            seen.add(name)
            L.append(f"add set inet netdeflect {name} {{ type {typ}; size {c.get('meter_size', 65535)}; flags {flags}; }}")
        # Meter sets of rules that expired: the flush above removed every rule
        # that used them, so they can go in the same transaction.
        for name in sorted(self._dyn_sets - seen):
            L.append(f"delete set inet netdeflect {name}")
        self._pending_dyn_sets = seen

        L.append("add chain inet netdeflect pre { type filter hook prerouting priority -300; policy accept; }")
        pre = ['iifname "lo" accept']
        ifaces = [i for i in c.get("interfaces", []) if i]
        if c.get("scope_rules_to_interfaces", True) and ifaces:
            pre.append("iifname != { %s } accept" % ", ".join(f'"{i}"' for i in ifaces))
        for peer in c.get("trusted_peers", []):
            fam = "ip6" if ":" in peer else "ip"
            pre.append(f"{fam} saddr {peer} accept")
        # auto-detected tunnel endpoints: only their tunnel protocol is accepted
        for peer, proto in c.get("tunnel_peers", []):
            fam = "ip6" if ":" in peer else "ip"
            pre.append(f"{fam} saddr {peer} meta l4proto {proto} accept")
        pre += ["ip saddr @blk4 counter drop", "ip6 saddr @blk6 counter drop",
                "ip saddr @blk4net counter drop", "ip6 saddr @blk6net counter drop",
                "ip saddr @drop4 counter drop", "ip6 saddr @drop6 counter drop"]
        if c.get("land_drop"):
            pre += ["ip saddr @own4 counter drop", "ip6 saddr @own6 counter drop"]
        if c.get("bogon_filter"):
            pre.append("ip saddr { %s } counter drop" % ", ".join(str(n) for n in BOGON_NETS_V4))
            pre.append("ip6 saddr { %s } counter drop" % ", ".join(str(n) for n in BOGON_NETS_V6))
        if c.get("drop_port0"):
            pre += ["udp dport 0 counter drop", "tcp dport 0 counter drop",
                    "udp sport 0 counter drop", "tcp sport 0 counter drop"]
        if c.get("block_all_ipv6"):
            pre.append("meta nfproto ipv6 counter drop")
        for port in sorted(c.get("bypass_ports", [])):
            pre += [f"udp dport {port} accept", f"tcp dport {port} accept"]
        if c.get("notrack_service_ports"):
            for svc in c.get("services", []):
                pexp = self._portexpr(sorted(svc["ports"]))
                for proto in (["udp", "tcp"] if svc["proto"] == "both" else [svc["proto"]]):
                    pre.append(f"{proto} dport {pexp} notrack")
        pre += svc_rules
        if c.get("exempt_resolvers", True):
            pre += ["ip saddr @res4 udp sport 53 accept", "ip6 saddr @res6 udp sport 53 accept"]
        fa = c.get("fragment_action", "off")
        if fa == "drop":
            pre += ["ip frag-off & 0x1fff != 0 counter drop", "exthdr frag exists counter drop"]
        elif fa == "ratelimit":
            r = c.get("fragment_rate_pps", 1000)
            pre += [f"ip frag-off & 0x1fff != 0 limit rate over {r}/second counter drop",
                    f"exthdr frag exists limit rate over {r}/second counter drop"]
        if c.get("blanket_udp_pps"):
            pre.append(f"meta l4proto udp limit rate over {c['blanket_udp_pps']}/second counter drop")
        if c.get("blanket_icmp_pps"):
            pre.append(f"meta l4proto {{ icmp, ipv6-icmp }} limit rate over {c['blanket_icmp_pps']}/second counter drop")
        for rule, _exp in self.active_filters.values():
            if not rule.needs_ct:
                pre += self._rule_strings(rule)
        L += [f"add rule inet netdeflect pre {line}" for line in pre]

        if c.get("enable_connection_tracking"):
            L.append("add chain inet netdeflect ctchain { type filter hook prerouting priority -150; policy accept; }")
            ctl = ['iifname "lo" accept']
            if c.get("scope_rules_to_interfaces", True) and ifaces:
                ctl.append("iifname != { %s } accept" % ", ".join(f'"{i}"' for i in ifaces))
            ctl.append("ct state established, related accept")
            if c.get("drop_invalid"):
                ctl.append("ct state invalid counter drop")
            if c.get("reflection_ct_drop"):
                ports = sorted(_reflection_sports(self.signatures))
                if ports:
                    ctl.append("udp sport { %s } ct state new counter drop" % ", ".join(map(str, ports)))
            if c.get("conn_limit_per_source") and c.get("conn_limit_ports"):
                ports = ", ".join(map(str, sorted(c["conn_limit_ports"])))
                cap = c["conn_limit_per_source"]
                L.append("add set inet netdeflect clp4 { type ipv4_addr; size 65535; flags dynamic; }")
                L.append("add set inet netdeflect clp6 { type ipv6_addr; size 65535; flags dynamic; }")
                ctl.append(f"tcp dport {{ {ports} }} ct state new add @clp4 {{ ip saddr ct count over {cap} }} counter drop")
                ctl.append(f"tcp dport {{ {ports} }} ct state new add @clp6 {{ ip6 saddr ct count over {cap} }} counter drop")
            for rule, _exp in self.active_filters.values():
                if rule.needs_ct:
                    ctl += self._rule_strings(rule)
            L += [f"add rule inet netdeflect ctchain {line}" for line in ctl]
        else:
            L.append("add chain inet netdeflect ctchain")
            L.append("delete chain inet netdeflect ctchain")
        return "\n".join(L) + "\n"

    def setup(self):
        with self.lock:
            if self.hook not in ("prerouting", ""):
                log.warning("nft_hook=%r is not supported; using prerouting (-300)", self.hook)
                self.hook = "prerouting"
            if not self._started:
                # Remove any table left by a previous run or an older version, so
                # a changed set definition can never make the load fail and leave
                # the server unprotected. In-run rebuilds keep their elements.
                self._nft("delete", "table", "inet", "netdeflect")
                self._started = True
                self._dyn_sets = set()
            rc, _, err = self._nft_script(self._render())
            if rc != 0 and not self.dry and self._dyn_sets - self._pending_dyn_sets:
                # The table was recreated underneath us (firewall restart), so the
                # stale meter sets we meant to delete no longer exist. Retry
                # without deleting them.
                self._dyn_sets = set()
                rc, _, err = self._nft_script(self._render())
            if rc != 0 and not self.dry:
                log.error("nft ruleset load failed (previous ruleset kept): %s", err.strip()[:400])
                return False
            self._dyn_sets = self._pending_dyn_sets
            return True

    def ensure_objects(self):
        rc, _, _ = self._run(["nft", "list", "table", "inet", "netdeflect"])
        if rc != 0:
            self.setup()

    def healthy(self):
        if self.dry:
            return True
        rc, _, _ = self._run(["nft", "list", "chain", "inet", "netdeflect", "pre"])
        return rc == 0

    def sync_filters(self):
        return self.setup()

    def _install_filter(self, rule):
        if rule.needs_ct and not self.cfg.get("enable_connection_tracking"):
            log.info("%s needs connection tracking (disabled in [conntrack]); "
                     "reported only", rule.name)
            return False
        return self.setup()

    # -- bans ---------------------------------------------------------------- #
    def _elem(self, item, to):
        return f"{item} timeout {int(to)}s" if to else item

    def _set_elements(self, setname):
        """{element: seconds left, or None when permanent} for one of our sets."""
        rc, text, _ = self._run(["nft", "-j", "list", "set", "inet", "netdeflect", setname])
        out = {}
        if rc != 0 or not text.strip():
            return out
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return out
        for item in data.get("nftables", []):
            for e in (item.get("set") or {}).get("elem", []) or []:
                left = None
                val = e
                if isinstance(e, dict) and "elem" in e:
                    val = e["elem"].get("val")
                    left = e["elem"].get("expires", e["elem"].get("timeout"))
                if isinstance(val, dict) and "prefix" in val:
                    val = f"{val['prefix']['addr']}/{val['prefix']['len']}"
                if isinstance(val, str):
                    out[_canon(val)] = left
        return out

    def _add_elements(self, setname, items, to):
        """Add elements, or extend ones already there. nft 'add element' leaves an
        existing element's timeout alone, so on its own a re-ban would not be
        extended and '--block --for 0' on an address with a timed ban would stay
        timed. An existing timed element is replaced when the new lifetime is
        longer (or permanent); a permanent one is never shortened."""
        if not items:
            return True
        items = list(dict.fromkeys(items))
        rc, err = 0, ""
        for _attempt in range(2):
            renew = []
            if not self.dry:
                cur = self._set_elements(setname)
                for x in items:
                    left = cur.get(_canon(x), "absent")
                    if left == "absent" or left is None:
                        continue
                    if not to or to > left + max(5, min(300, to // 20)):
                        renew.append(x)
            lines = []
            for i in range(0, len(renew), 1000):
                lines.append(f"delete element inet netdeflect {setname} {{ {', '.join(renew[i:i + 1000])} }}")
            for i in range(0, len(items), 1000):
                chunk = ", ".join(self._elem(x, to) for x in items[i:i + 1000])
                lines.append(f"add element inet netdeflect {setname} {{ {chunk} }}")
            rc, _, err = self._nft_script("\n".join(lines) + "\n")
            if rc == 0 or not renew:
                break
            # an element expired between listing and deleting it; list again
        if rc != 0 and not self.dry:
            log.warning("nft could not add %d element(s) to %s: %s", len(items), setname, err.strip()[:200])
        return rc == 0

    def block_many(self, ips, timeout=None):
        to = self.timeout if timeout is None else timeout
        v4 = [ip for ip in ips if ":" not in ip]
        v6 = [ip for ip in ips if ":" in ip]
        ok4 = self._add_elements("blk4", v4, to)
        ok6 = self._add_elements("blk6", v6, to)
        return (v4 if ok4 else []) + (v6 if ok6 else [])

    def block_net_many(self, nets, timeout=None):
        to = self.timeout if timeout is None else timeout
        v4 = [n for n in nets if ":" not in n]
        v6 = [n for n in nets if ":" in n]
        ok4 = self._add_elements("blk4net", v4, to)
        ok6 = self._add_elements("blk6net", v6, to)
        return (v4 if ok4 else []) + (v6 if ok6 else [])

    def block_src(self, ip, timeout=None):
        return bool(self.block_many([ip], timeout))

    def block_net(self, net, timeout=None):
        return bool(self.block_net_many([net], timeout))

    def add_known_clients(self, ips, ttl):
        v4 = [ip for ip in ips if ":" not in ip]
        v6 = [ip for ip in ips if ":" in ip]
        self._add_elements("known4", v4, ttl)
        self._add_elements("known6", v6, ttl)
        return len(ips)

    def unblock_src(self, ip):
        ok = False
        for setname in (("blk6", "blk6net") if ":" in ip else ("blk4", "blk4net")):
            rc, _, _ = self._nft("delete", "element", "inet", "netdeflect", setname, f"{{ {ip} }}")
            ok = ok or rc == 0
        if not ok:
            rc, out, _ = self._nft("get", "element", "inet", "netdeflect",
                                   "blk6net" if ":" in ip else "blk4net", f"{{ {ip} }}")
            if rc == 0:
                log.warning("%s is still covered by a blocked subnet: %s", ip, out.strip())
        return ok

    def list_blocks(self):
        out = []
        for setname in ("blk4", "blk6", "blk4net", "blk6net"):
            rc, text, _ = self._run(["nft", "-j", "list", "set", "inet", "netdeflect", setname])
            if rc != 0 or not text.strip():
                continue
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                continue
            for item in data.get("nftables", []):
                for e in (item.get("set") or {}).get("elem", []) or []:
                    val = e.get("elem", {}).get("val") if isinstance(e, dict) and "elem" in e else e
                    if isinstance(val, dict) and "prefix" in val:
                        out.append(f"{val['prefix']['addr']}/{val['prefix']['len']}")
                    elif isinstance(val, str):
                        out.append(val)
        return out

    def dropped_packets(self):
        rc, out, _ = self._run(["nft", "-j", "list", "table", "inet", "netdeflect"])
        if rc != 0 or not out.strip():
            return None
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return None
        total = 0
        for item in data.get("nftables", []):
            rule = item.get("rule")
            if not rule:
                continue
            for expr in rule.get("expr", []):
                if "counter" in expr:
                    total += expr["counter"].get("packets", 0)
        return total

    def teardown(self):
        if not self.dry:
            self._nft("delete", "table", "inet", "netdeflect")


def _is_loopback(ip):
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return True


def _canon(item):
    """One spelling per address or range, so sets, nft output and xdp-filter
    output compare equal ('2001:DB8::1' and '2001:db8:0::1' are the same host)."""
    try:
        if "/" in item:
            net = ipaddress.ip_network(item, strict=False)
            if net.prefixlen == net.max_prefixlen:
                return str(net.network_address)
            return str(net)
        return str(ipaddress.ip_address(item))
    except ValueError:
        return item


def _reflection_sports(signatures):
    ports = set()
    for s in signatures:
        if s.category in ("reflection", "amplification") and s.sports and s.proto == 17:
            ports |= s.sports
    return ports


# ---- XDP acceleration (xdp-tools / xdp-filter) ----------------------------- #

class XdpFirewall(NftFirewall):
    """Optional XDP fast path layered on the nftables backend.

    nftables does all of the classification and pattern dropping exactly as the
    default backend. On top of that, the banned SOURCE addresses are mirrored into
    xdp-tools' `xdp-filter`, which drops them in the NIC driver (XDP) before the
    packet ever reaches the kernel's network stack or netfilter.

    nftables is the single source of truth. The XDP drop map is kept as an exact
    mirror of (a bounded part of) the host bans in nftables: it is reconciled
    against what xdp-filter actually holds, so an address leaves XDP no later than
    it leaves nftables, whether its ban expired, it was unblocked from the command
    line, or an earlier run crashed and left entries behind.

      * Strictly additive and fail-safe: every XDP drop is for an address nftables
        is already dropping. If xdp-filter is missing, a load fails, or any XDP
        call errors, NetDeflect runs as the plain nftables backend.
      * xdp-filter is always loaded with the `allow` policy (only the addresses we
        add are dropped; everything else passes), so it can never black-hole the
        box the way a default-deny load could.
      * xdp-filter is loaded once and left in place; rule changes only touch
        nftables, so the XDP working set is not thrown away mid-attack.
      * xdp-filter matches addresses, not packet shape, and holds at most 10000
        addresses per family. Spoofed-source floods, byte-pattern rules and CIDR
        ranges stay on nftables, which has no such limits.

    Needs the `xdp-tools` package and an interface whose driver supports XDP
    (native, or skb/generic as a fallback)."""

    MAP_LIMIT = 10000          # xdp-filter's filter_ipv4 / filter_ipv6 map size
    SYNC_INTERVAL = 10         # seconds between full reconciliations with nftables
    EXPIRY_MARGIN = 10         # leave XDP this long before nftables does
    WORKERS = 8                # parallel xdp-filter calls (one process per address)
    BPFFS = "/sys/fs/bpf"

    def __init__(self, cfg):
        super().__init__(cfg)
        self.xdp_bin = shutil.which("xdp-filter")
        self.xdp_ifaces = []       # interfaces xdp-filter is loaded on
        self._xdp_ips = {}         # ip -> epoch it must leave XDP by (inf = permanent)
        self._xdp_loaded_for = None
        self._xdp_last_sync = 0.0
        self._xdp_prev = None      # (XDP_DROP count, time) for pre_capture_drop_rate
        self._xdp_warned = False
        self.apply_config(cfg)

    def apply_config(self, cfg):
        super().apply_config(cfg)
        self.xdp_mode = cfg.get("xdp_mode", "native")
        self.xdp_cap = min(max(0, cfg.get("xdp_max_entries", 4000)), self.MAP_LIMIT)
        self.xdp_per_round = max(1, cfg.get("xdp_adds_per_round", 512))

    # -- xdp-filter plumbing ------------------------------------------------- #
    def _xdp(self, *args):
        return self._run([self.xdp_bin] + list(args))

    def _xdp_many(self, calls):
        """Run several xdp-filter calls in parallel; returns [ok, ...]."""
        if not calls:
            return []
        if len(calls) == 1:
            return [self._xdp(*calls[0])[0] == 0]
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=self.WORKERS) as pool:
            return [rc == 0 for rc, _, _ in pool.map(lambda a: self._xdp(*a), calls)]

    def _xdp_ready(self):
        return bool(self.xdp_bin) and bool(self.xdp_ifaces) and not self.dry

    def _maps_present(self):
        """True when an xdp-filter instance (normally the running daemon's) has
        its drop maps pinned, so this process can edit them too."""
        base = os.path.join(self.BPFFS, "xdp-filter")
        return os.path.exists(os.path.join(base, "filter_ipv4")) or \
            os.path.exists(os.path.join(base, "filter_ipv6"))

    def _status(self):
        rc, out, _ = self._xdp("status")
        return out if rc == 0 else None

    @staticmethod
    def _status_entries(out):
        """Source addresses listed in `xdp-filter status` output."""
        ips = set()
        if not out or "Filtered IP addresses:" not in out:
            return ips
        for line in out.split("Filtered IP addresses:", 1)[1].splitlines():
            m = re.match(r"\s+(\S+)\s+(src|dst|src,dst|dst,src)\s+\d+", line)
            if m:
                if "src" in m.group(2):
                    ips.add(_canon(m.group(1)))
            elif line.strip().startswith("Filtered "):
                break
        return ips

    @staticmethod
    def _status_drops(out):
        m = re.search(r"XDP_DROP\s+(\d+)\s+pkts", out or "")
        return int(m.group(1)) if m else None

    def _attached(self, iface):
        r = self._run(["ip", "-d", "link", "show", "dev", iface])
        return r[0] == 0 and "prog/xdp" in r[1]

    def _ensure_bpffs(self):
        """xdp-filter pins its maps in bpffs. systemd mounts it at /sys/fs/bpf,
        but containers, minimal VMs and WSL often do not."""
        if os.path.ismount(self.BPFFS):
            return True
        try:
            os.makedirs(self.BPFFS, exist_ok=True)
        except OSError:
            pass
        rc, _, err = self._run(["mount", "-t", "bpf", "bpf", self.BPFFS])
        if rc == 0:
            log.info("Mounted the BPF filesystem at %s (xdp-filter keeps its drop map there)",
                     self.BPFFS)
            return True
        log.warning("The BPF filesystem is not mounted at %s and could not be mounted (%s); "
                    "xdp-filter cannot load, so the nftables drop path is used.",
                    self.BPFFS, err.strip()[:160])
        return False

    # -- crash cleanup state -------------------------------------------------- #
    @staticmethod
    def _state_path():
        return os.path.join(DATA_DIR, "xdp_interfaces.json")

    def _state_ifaces(self):
        try:
            with open(self._state_path(), encoding="utf-8") as fh:
                return [i for i in json.load(fh).get("interfaces", []) if isinstance(i, str)]
        except (OSError, ValueError, AttributeError):
            return []

    def _save_state(self, ifaces):
        """Record where xdp-filter is loaded so uninstall_rules.sh (systemd
        ExecStopPost) can unload it if NetDeflect is killed."""
        try:
            if ifaces:
                os.makedirs(os.path.dirname(self._state_path()), exist_ok=True)
                tmp = self._state_path() + ".tmp"
                with open(tmp, "w", encoding="utf-8") as fh:
                    json.dump({"interfaces": sorted(ifaces)}, fh)
                os.replace(tmp, self._state_path())
            elif os.path.exists(self._state_path()):
                os.remove(self._state_path())
        except OSError:
            pass

    # -- loading -------------------------------------------------------------- #
    def _xdp_load(self):
        """Load xdp-filter (allow policy: only added addresses drop) on each
        protected interface that does not already have it. Already-loaded
        interfaces are left alone so their drop map survives rule changes."""
        want = [i for i in self.cfg.get("interfaces", []) if i]
        if not self.xdp_bin:
            if not self._xdp_warned:
                log.warning("firewall_system=xdp but xdp-filter is not installed (package "
                            "xdp-tools); running as the nftables backend only. Install "
                            "xdp-tools to drop banned sources in the NIC driver with XDP.")
                self._xdp_warned = True
            self.xdp_ifaces = []
            return
        if self.dry:
            return
        first = self._xdp_loaded_for is None
        if (not first and self._xdp_loaded_for == tuple(want) and self.xdp_ifaces
                and all(self._attached(i) for i in self.xdp_ifaces)):
            return
        if not self._ensure_bpffs():
            self.xdp_ifaces = []
            return
        # First load: start from an empty map (unload everything this or a
        # crashed run loaded). Later: only unload interfaces no longer protected.
        stale = set(self._state_ifaces()) | set(self.xdp_ifaces)
        if first:
            stale |= set(want)
        else:
            stale -= set(want)
        for iface in sorted(stale):
            self._xdp("unload", iface)
        loaded = [] if first else [i for i in self.xdp_ifaces if i in want and self._attached(i)]
        modes = {"hw": ["hw", "native", "skb"], "skb": ["skb"]}.get(self.xdp_mode, ["native", "skb"])
        for iface in want:
            if iface in loaded:
                continue
            err = ""
            for mode in modes:
                rc, _, err = self._xdp("load", "-m", mode, "-p", "allow", "-f", "ipv4,ipv6", iface)
                if rc == 0:
                    loaded.append(iface)
                    log.info("xdp-filter loaded on %s (%s mode): banned sources now drop "
                             "in the NIC driver (XDP) before netfilter", iface, mode)
                    break
                log.debug("xdp-filter load (%s) on %s failed: %s", mode, iface, err.strip()[:160])
            else:
                log.warning("xdp-filter could not load on %s (%s); that interface uses the "
                            "nftables drop path only.", iface, err.strip()[:200] or "no error text")
        self.xdp_ifaces = loaded
        self._xdp_loaded_for = tuple(want)
        self._save_state(loaded)
        self._xdp_ips = {}
        self._xdp_last_sync = 0.0
        if loaded:
            self._xdp_sync(force=True)

    # -- reconciliation ------------------------------------------------------- #
    def _nft_bans(self):
        """{ip: epoch it must leave XDP by} for every host ban in nftables."""
        now = time.time()
        out = {}
        for setname in ("blk4", "blk6"):
            for ip, left in self._set_elements(setname).items():
                if "/" in ip:
                    continue
                out[ip] = float("inf") if left is None else now + left - self.EXPIRY_MARGIN
        return out

    def _xdp_sync(self, force=False, prefer=()):
        """Make the XDP map an exact mirror of a bounded subset of the nftables
        host bans: remove whatever nftables no longer bans (expired, unblocked,
        left over from an earlier run), then add the most important missing ones
        (this round's heaviest sources first, then permanent bans, then the
        longest-lived), up to xdp_adds_per_round and xdp_max_entries."""
        if not self._xdp_ready():
            return
        now = time.time()
        if not force and now - self._xdp_last_sync < self.SYNC_INTERVAL:
            return
        self._xdp_last_sync = now
        have = self._status_entries(self._status())
        want = {ip: exp for ip, exp in self._nft_bans().items() if exp > now}
        stale = sorted(have - set(want))
        self._xdp_many([("ip", ip, "-r", "-m", "src") for ip in stale])
        self._xdp_ips = {ip: want[ip] for ip in have if ip in want}
        room = min(self.xdp_cap - len(self._xdp_ips), self.xdp_per_round)
        adds = []
        if room > 0:
            seen = set(self._xdp_ips)
            ranked = [_canon(ip) for ip in prefer] + sorted(want, key=lambda ip: -want[ip])
            for ip in ranked:
                if ip in want and ip not in seen:
                    seen.add(ip)
                    adds.append(ip)
                    if len(adds) >= room:
                        break
        for ip, ok in zip(adds, self._xdp_many([("ip", ip, "-m", "src") for ip in adds])):
            if ok:
                self._xdp_ips[ip] = want[ip]
        if stale or adds:
            log.debug("XDP sync: %d removed, %d added, %d held (of %d nftables bans)",
                      len(stale), len(adds), len(self._xdp_ips), len(want))

    def xdp_dropped(self):
        """Packets xdp-filter has dropped (all interfaces), or None."""
        if not self.xdp_bin or self.dry or not self._maps_present():
            return None
        return self._status_drops(self._status())

    def pre_capture_drop_rate(self):
        x = self.xdp_dropped()
        now = time.time()
        prev, self._xdp_prev = self._xdp_prev, ((x, now) if x is not None else None)
        if x is None or prev is None or now <= prev[1] or x < prev[0]:
            return 0
        return (x - prev[0]) / (now - prev[1])

    # -- overrides: nftables stays authoritative; XDP mirrors source bans ------ #
    def setup(self):
        ok = super().setup()
        try:
            with self.lock:
                self._xdp_load()
        except Exception as exc:  # noqa: BLE001 - XDP must never break protection
            log.warning("xdp-filter setup skipped (%s); nftables protection is active", exc)
            self.xdp_ifaces = []
        return ok

    def ensure_objects(self):
        """Command-line use: make sure the nftables table exists, but never load
        XDP here. The running daemon owns the XDP program."""
        rc, _, _ = self._run(["nft", "list", "table", "inet", "netdeflect"])
        if rc != 0:
            NftFirewall.setup(self)

    def block_many(self, ips, timeout=None):
        done = super().block_many(ips, timeout)
        try:
            with self.lock:
                if self._xdp_ready():
                    self._xdp_sync(force=True, prefer=done)
                elif done and not self.dry and self.xdp_bin and self._maps_present():
                    # command line, with the daemon running: put a manual block
                    # straight into the daemon's XDP map (it reconciles later)
                    hosts = [ip for ip in done if "/" not in ip][:16]
                    self._xdp_many([("ip", ip, "-m", "src") for ip in hosts])
        except Exception:  # noqa: BLE001
            pass
        return done

    def unblock_src(self, ip):
        ok = super().unblock_src(ip)
        try:
            with self.lock:
                if self.xdp_bin and not self.dry and (self.xdp_ifaces or self._maps_present()):
                    self._xdp("ip", ip, "-r", "-m", "src")
                self._xdp_ips.pop(_canon(ip), None)
        except Exception:  # noqa: BLE001
            pass
        return ok

    def _cleanup_blocked(self, now):
        super()._cleanup_blocked(now)
        if not self._xdp_ready():
            return
        expired = [ip for ip, e in self._xdp_ips.items() if e <= now]
        if expired:
            self._xdp_many([("ip", ip, "-r", "-m", "src") for ip in expired])
            for ip in expired:
                self._xdp_ips.pop(ip, None)
        if now - self._xdp_last_sync >= self.SYNC_INTERVAL:
            if not all(self._attached(i) for i in self.xdp_ifaces):
                log.warning("xdp-filter was removed from %s by another program; loading it again",
                            ", ".join(self.xdp_ifaces))
                self._xdp_load()
            else:
                self._xdp_sync()

    def dropped_packets(self):
        base = super().dropped_packets()
        x = self.xdp_dropped()
        if base is None and x is None:
            return None
        return (base or 0) + (x or 0)

    def healthy(self):
        return super().healthy()   # nftables is the authority; XDP is re-checked in cleanup

    def teardown(self):
        if not self.dry and self.xdp_bin:
            for iface in sorted(set(self.xdp_ifaces) | set(self._state_ifaces())):
                try:
                    self._xdp("unload", iface)
                except Exception:  # noqa: BLE001
                    pass
            self._save_state([])
        self.xdp_ifaces = []
        self._xdp_ips = {}
        self._xdp_loaded_for = None
        super().teardown()


# ---- iptables (+ optional ipset) ------------------------------------------ #

class IptablesFirewall(BaseFirewall):
    CHAIN = "NETDEFLECT"
    SRC = "NETDEFLECT_SRC"       # source bans; never flushed by a rule rebuild
    SETS = {"blk4": ("nd_blocked4", "hash:ip", "inet"), "blk6": ("nd_blocked6", "hash:ip", "inet6"),
            "net4": ("nd_blockednet4", "hash:net", "inet"), "net6": ("nd_blockednet6", "hash:net", "inet6"),
            "drop4": ("nd_drop4", "hash:net", "inet"), "drop6": ("nd_drop6", "hash:net", "inet6"),
            "known4": ("nd_known4", "hash:ip", "inet"), "known6": ("nd_known6", "hash:ip", "inet6")}
    supports_payload_match = True

    def __init__(self, cfg, use_ipset=True):
        super().__init__(cfg)
        self.use_ipset = use_ipset and bool(shutil.which("ipset"))
        if use_ipset and not self.use_ipset:
            log.warning("ipset not found; source bans use a dedicated iptables chain "
                        "(slower with many entries). Install ipset or use nftables.")

    def _tools(self):
        return ["iptables"] + (["ip6tables"] if shutil.which("ip6tables") else [])

    @staticmethod
    def _ipt_for(item):
        return "ip6tables" if ":" in item else "iptables"

    def _set(self, key):
        return self.SETS[key][0]

    def unsupported_fields(self, rule):
        bad = []
        pname = PROTO_NUM_TO_IPT.get(rule.proto)
        if isinstance(rule.tcp_mss, str):
            bad.append("tcp_mss missing")
        if rule.tcp_window is not None:
            bad.append("tcp_window")
        if rule.tcp_reserved is not None:
            bad.append("tcp_reserved")
        if rule.payload_mask is not None:
            bad.append("payload_mask")
        if rule.payload is not None and pname != "udp":
            bad.append("non-UDP payload")
        if rule.frag == "first":
            bad.append("first-fragment match")
        if rule.strategy == "conn_limit":
            bad.append("per-source connection cap")
        return bad

    # -- setup --------------------------------------------------------------- #
    def _hooks(self):
        ifaces = [i for i in self.cfg.get("interfaces", []) if i]
        if self.cfg.get("scope_rules_to_interfaces", True) and ifaces:
            return [["-i", i] for i in ifaces]
        return [[]]

    def setup(self):
        with self.lock:
            if self.use_ipset:
                for key, (name, typ, fam) in self.SETS.items():
                    extra = ["timeout", "0"] if key in ("blk4", "blk6", "net4", "net6", "known4", "known6") else []
                    self._run(["ipset", "create", name, typ, "family", fam, "maxelem", "1048576"] + extra + ["-exist"])
                self._load_drop_sets()
            for ipt in self._tools():
                for ch in (self.SRC, self.CHAIN):
                    self._run([ipt, "-t", "raw", "-N", ch])
                self._run([ipt, "-t", "raw", "-F", self.CHAIN])
                for ch in (self.SRC, self.CHAIN):
                    for h in self._hooks():
                        rc, _, _ = self._run([ipt, "-t", "raw", "-C", "PREROUTING"] + h + ["-j", ch])
                        if rc != 0:
                            self._run([ipt, "-t", "raw", "-A", "PREROUTING"] + h + ["-j", ch])
            self._rebuild_src()
            self._add_base_rules()
            for rule, _exp in self.active_filters.values():
                self._install_rule(rule)
            self._sync_conntrack_rule()
            return True

    def ensure_objects(self):
        rc, _, _ = self._run(["iptables", "-t", "raw", "-L", self.CHAIN])
        if rc != 0:
            self.setup()

    def healthy(self):
        if self.dry:
            return True
        h = self._hooks()[0]
        rc, _, _ = self._run(["iptables", "-t", "raw", "-C", "PREROUTING"] + h + ["-j", self.CHAIN])
        return rc == 0

    def _load_drop_sets(self):
        lines = []
        for key, items in (("drop4", self.static_drop4), ("drop6", self.static_drop6)):
            name = self._set(key)
            lines.append(f"flush {name}")
            lines += [f"add {name} {i}" for i in items]
        self._run(["ipset", "restore", "-exist"], input_text="\n".join(lines) + "\n")

    def _sync_conntrack_rule(self):
        want = self.cfg.get("enable_connection_tracking") and self.cfg.get("drop_invalid")
        spec = ["-m", "conntrack", "--ctstate", "INVALID", "-m", "comment",
                "--comment", "netdeflect", "-j", "DROP"]
        for ipt in self._tools():
            rc, _, _ = self._run([ipt, "-t", "mangle", "-C", "PREROUTING"] + spec)
            if want and rc != 0:
                self._run([ipt, "-t", "mangle", "-I", "PREROUTING"] + spec)
            elif not want and rc == 0:
                self._run([ipt, "-t", "mangle", "-D", "PREROUTING"] + spec)

    def _add(self, ipt, args):
        rc, _, err = self._run([ipt, "-t", "raw", "-A", self.CHAIN] + args)
        if rc != 0 and not self.dry:
            log.warning("%s rule rejected: %s (%s)", ipt, " ".join(args), err.strip()[:120])
        return rc == 0

    def _add_base_rules(self):
        c = self.cfg
        both = self._tools()
        if not (c.get("scope_rules_to_interfaces", True) and c.get("interfaces")):
            for ipt in both:
                self._add(ipt, ["-i", "lo", "-j", "ACCEPT"])
        for peer in c.get("trusted_peers", []):
            self._add(self._ipt_for(peer), ["-s", peer, "-j", "ACCEPT"])
        for peer, proto in c.get("tunnel_peers", []):
            if ":" not in peer or "ip6tables" in both:
                self._add(self._ipt_for(peer), ["-s", peer, "-p", str(proto), "-j", "ACCEPT"])
        if self.use_ipset:
            for key in ("blk4", "net4", "drop4"):
                self._add("iptables", ["-m", "set", "--match-set", self._set(key), "src", "-j", "DROP"])
            if "ip6tables" in both:
                for key in ("blk6", "net6", "drop6"):
                    self._add("ip6tables", ["-m", "set", "--match-set", self._set(key), "src", "-j", "DROP"])
        if c.get("land_drop"):
            for ip in sorted(self.own_ips):
                if not _is_loopback(ip) and (":" not in ip or "ip6tables" in both):
                    self._add(self._ipt_for(ip), ["-s", ip, "-j", "DROP"])
        if c.get("bogon_filter"):
            for n in BOGON_NETS_V4:
                self._add("iptables", ["-s", str(n), "-j", "DROP"])
        if c.get("drop_port0"):
            for ipt in both:
                for proto in ("udp", "tcp"):
                    self._add(ipt, ["-p", proto, "--dport", "0", "-j", "DROP"])
                    self._add(ipt, ["-p", proto, "--sport", "0", "-j", "DROP"])
        if c.get("block_all_ipv6") and "ip6tables" in both:
            self._add("ip6tables", ["-j", "DROP"])
        for port in sorted(c.get("bypass_ports", [])):
            for ipt in both:
                for proto in ("udp", "tcp"):
                    self._add(ipt, ["-p", proto, "--dport", str(port), "-j", "ACCEPT"])
        self._add_service_rules(both)
        if c.get("exempt_resolvers", True):
            for r in sorted(self.resolvers):
                if ":" not in r or "ip6tables" in both:
                    self._add(self._ipt_for(r), ["-s", r, "-p", "udp", "--sport", "53", "-j", "ACCEPT"])
        fa = c.get("fragment_action", "off")
        if fa == "drop":
            self._add("iptables", ["-f", "-j", "DROP"])
        elif fa == "ratelimit":
            r = c.get("fragment_rate_pps", 1000)
            self._add("iptables", ["-f", "-m", "hashlimit", "--hashlimit-above", f"{r}/sec",
                                   "--hashlimit-name", "ndfrag", "-j", "DROP"])
        if c.get("blanket_udp_pps"):
            for ipt in both:
                self._add(ipt, ["-p", "udp", "-m", "hashlimit", "--hashlimit-above",
                                f"{c['blanket_udp_pps']}/sec", "--hashlimit-name", "ndblanketudp", "-j", "DROP"])
        if c.get("blanket_icmp_pps"):
            self._add("iptables", ["-p", "icmp", "-m", "hashlimit", "--hashlimit-above",
                                   f"{c['blanket_icmp_pps']}/sec", "--hashlimit-name", "ndblanketicmp", "-j", "DROP"])

    def _add_service_rules(self, both):
        c = self.cfg
        for svc in c.get("services", []):
            ports = ",".join(map(str, sorted(svc["ports"])[:15]))
            pm = ["-m", "multiport", "--dports", ports]
            protos = ["udp", "tcp"] if svc["proto"] == "both" else [svc["proto"]]
            for proto in protos:
                syn = ["--syn"] if proto == "tcp" else []
                for ipt in both:
                    v6 = ipt == "ip6tables"
                    base = ["-p", proto] + pm
                    if proto == "udp" and svc.get("preset") == "wireguard":
                        self._add(ipt, base + ["-m", "u32", "!", "--u32",
                                               ("0>>22&0x3C@8=0x01000000,0x02000000,0x03000000,0x04000000"
                                                if not v6 else "48=0x01000000,0x02000000,0x03000000,0x04000000"),
                                               "-j", "DROP"])
                    if proto == "udp" and svc.get("preset") == "openvpn":
                        self._add(ipt, base + ["-m", "u32", "!", "--u32",
                                               ("0>>22&0x3C@8>>27=1:11" if not v6 else "48>>27=1:11"),
                                               "-j", "DROP"])
                    if svc.get("min_len") or svc.get("max_len"):
                        self._add(ipt, base + ["-m", "length", "!", "--length",
                                               f"{svc.get('min_len') or 0}:{svc.get('max_len') or 65535}",
                                               "-j", "DROP"])
                    lock = self.lockdown and svc.get("lockdown", True)
                    tag = svc["name"][:8]
                    if c.get("learn_known_clients") and svc.get("lockdown", True) and self.use_ipset:
                        kset = self._set("known6" if v6 else "known4")
                        kr = svc.get("known_rate_pps", 0)
                        if kr:
                            self._add(ipt, base + syn + ["-m", "set", "--match-set", kset, "src",
                                                          "-m", "hashlimit", "--hashlimit-above", f"{kr}/sec",
                                                          "--hashlimit-burst", str(kr * 2), "--hashlimit-mode", "srcip",
                                                          "--hashlimit-name", f"ndkc{tag}", "-j", "DROP"])
                        self._add(ipt, base + ["-m", "set", "--match-set", kset, "src", "-j", "ACCEPT"])
                    if lock:
                        lr = c.get("lockdown_rate_pps", 50)
                        if lr:
                            self._add(ipt, base + syn + ["-m", "hashlimit", "--hashlimit-above", f"{lr}/sec",
                                                         "--hashlimit-burst", str(lr * 2), "--hashlimit-mode", "srcip",
                                                         "--hashlimit-name", f"ndlk{tag}", "-j", "DROP"])
                        t = c.get("lockdown_total_pps", 0)
                        if t:
                            self._add(ipt, base + syn + ["-m", "hashlimit", "--hashlimit-above", f"{t}/sec",
                                                         "--hashlimit-burst", str(t), "--hashlimit-name",
                                                         f"ndlt{tag}", "-j", "DROP"])
                    elif svc.get("rate_pps"):
                        r = svc["rate_pps"]
                        self._add(ipt, base + syn + ["-m", "hashlimit", "--hashlimit-above", f"{r}/sec",
                                                     "--hashlimit-burst", str(r * 2), "--hashlimit-mode", "srcip",
                                                     "--hashlimit-name", f"ndsv{tag}", "-j", "DROP"])

    # -- source bans ----------------------------------------------------------- #
    def _rebuild_src(self):
        if self.use_ipset:
            return
        for ipt in self._tools():
            self._run([ipt, "-t", "raw", "-F", self.SRC])
            if not (self.cfg.get("scope_rules_to_interfaces", True) and self.cfg.get("interfaces")):
                self._run([ipt, "-t", "raw", "-A", self.SRC, "-i", "lo", "-j", "RETURN"])
        for item in list(self.blocked):
            self._run([self._ipt_for(item), "-t", "raw", "-A", self.SRC, "-s", item, "-j", "DROP"])

    def _ipset_add(self, key4, key6, items, to):
        lines = []
        for it in items:
            name = self._set(key6 if ":" in it else key4)
            lines.append(f"add {name} {it} timeout {int(to or 0)}")
        if not lines:
            return []
        rc, _, err = self._run(["ipset", "restore", "-exist"], input_text="\n".join(lines) + "\n")
        if rc != 0 and not self.dry:
            log.warning("ipset restore failed: %s", err.strip()[:200])
            return []
        return list(items)

    def block_many(self, ips, timeout=None):
        to = self.timeout if timeout is None else timeout
        if self.use_ipset:
            return self._ipset_add("blk4", "blk6", ips, to)
        done = []
        for ip in ips:
            if ip not in self.blocked:
                rc, _, _ = self._run([self._ipt_for(ip), "-t", "raw", "-A", self.SRC, "-s", ip, "-j", "DROP"])
                if rc != 0:
                    continue
            self.blocked[ip] = (time.time() + to) if to else float("inf")
            done.append(ip)
        return done

    def block_net_many(self, nets, timeout=None):
        to = self.timeout if timeout is None else timeout
        if self.use_ipset:
            return self._ipset_add("net4", "net6", nets, to)
        return self.block_many(nets, timeout)

    def block_src(self, ip, timeout=None):
        return bool(self.block_many([ip], timeout))

    def block_net(self, net, timeout=None):
        return bool(self.block_net_many([net], timeout))

    def add_known_clients(self, ips, ttl):
        if self.use_ipset:
            self._ipset_add("known4", "known6", ips, ttl)
        return len(ips)

    def unblock_src(self, ip):
        if self.use_ipset:
            for key in (("blk6", "net6") if ":" in ip else ("blk4", "net4")):
                self._run(["ipset", "del", self._set(key), ip, "-exist"])
            return True
        while True:
            rc, _, _ = self._run([self._ipt_for(ip), "-t", "raw", "-D", self.SRC, "-s", ip, "-j", "DROP"])
            if rc != 0:
                break
        self.blocked.pop(ip, None)
        return True

    def list_blocks(self):
        out = []
        if self.use_ipset:
            for key in ("blk4", "blk6", "net4", "net6"):
                rc, text, _ = self._run(["ipset", "list", self._set(key)])
                if rc == 0 and "Members:" in text:
                    out += [m.split()[0] for m in text.split("Members:", 1)[1].splitlines() if m.strip()]
        else:
            for ipt in self._tools():
                rc, text, _ = self._run([ipt, "-t", "raw", "-S", self.SRC])
                if rc == 0:
                    for line in text.splitlines():
                        toks = line.split()
                        if "-s" in toks and "DROP" in toks:
                            out.append(toks[toks.index("-s") + 1])
        return [e.rsplit("/", 1)[0] if e.endswith(("/32", "/128")) else e for e in out]

    # -- pattern rules ----------------------------------------------------------- #
    def _rule_args(self, rule, pname, v6):
        base = []
        if rule.src_net is not None:
            base += ["-s", str(rule.src_net)]
        if rule.dst_net is not None:
            base += ["-d", str(rule.dst_net)]
        if pname:
            base += ["-p", pname]
        elif rule.proto is not None:
            base += ["-p", str(rule.proto)]
        if rule.sports and pname in ("tcp", "udp"):
            base += (["--sport", str(rule.sports[0])] if len(rule.sports) == 1
                     else ["-m", "multiport", "--sports", ",".join(map(str, rule.sports[:15]))])
        if rule.dports and pname in ("tcp", "udp"):
            base += (["--dport", str(rule.dports[0])] if len(rule.dports) == 1
                     else ["-m", "multiport", "--dports", ",".join(map(str, rule.dports[:15]))])
        if rule.flags_value is not None and pname == "tcp":
            names = flag_value_to_names(rule.flags_value & TCP_CORE_MASK)
            mask = flag_value_to_names(rule.flags_mask & TCP_CORE_MASK) or ["FIN", "SYN", "RST", "PSH", "ACK", "URG"]
            base += ["--tcp-flags", ",".join(mask), ",".join(names) if names else "NONE"]
            if rule.flags_mask & 0x40:
                base += ["-m", "ecn"] + (["--ecn-tcp-ece"] if rule.flags_value & 0x40 else ["!", "--ecn-tcp-ece"])
            if rule.flags_mask & 0x80:
                base += ["-m", "ecn"] + (["--ecn-tcp-cwr"] if rule.flags_value & 0x80 else ["!", "--ecn-tcp-cwr"])
        if pname in ("icmp", "icmpv6") and rule.icmp_type is not None:
            typ = str(rule.icmp_type) + (f"/{rule.icmp_code}" if rule.icmp_code is not None else "")
            base += (["--icmpv6-type", typ] if pname == "icmpv6" else ["--icmp-type", typ])
        if rule.min_len or rule.max_len:
            base += ["-m", "length", "--length", f"{rule.min_len or 0}:{rule.max_len or 65535}"]
        if rule.ttl_min is not None or rule.ttl_max is not None:
            mod = "hl" if v6 else "ttl"
            lo, hi = rule.ttl_min, rule.ttl_max
            if lo is not None and lo == hi:
                base += ["-m", mod, f"--{mod}-eq", str(lo)]
            else:
                if lo is not None and lo > 0:
                    base += ["-m", mod, f"--{mod}-gt", str(lo - 1)]
                if hi is not None and hi < 255:
                    base += ["-m", mod, f"--{mod}-lt", str(hi + 1)]
        if rule.tos is not None:
            base += ["-m", "dscp", "--dscp", str(rule.tos >> 2)]
        if rule.tcp_mss is not None and pname == "tcp" and not isinstance(rule.tcp_mss, str):
            mss = f"{rule.tcp_mss[0]}:{rule.tcp_mss[1]}" if isinstance(rule.tcp_mss, (list, tuple)) else str(rule.tcp_mss)
            base += ["-m", "tcpmss", "--mss", mss]
        if rule.frag in ("later", "any") and not v6:
            base += ["-f"]
        if rule.payload is not None and pname == "udp":
            frm = (48 if v6 else 28) + (rule.payload_offset or 0)
            base += ["-m", "string", "--algo", "bm", "--from", str(frm),
                     "--to", str(frm + len(rule.payload) + (0 if rule.payload_offset is not None else 64)),
                     "--hex-string", f"|{rule.payload.hex()}|"]
        if rule.strategy == "allow":
            return base + ["-j", "ACCEPT"]
        if rule.strategy in ("ratelimit", "syn"):
            rate = rule.rate_pps or 50
            if rule.strategy == "syn" and rule.flags_value is None:
                base += ["--syn"]
            return base + ["-m", "hashlimit", "--hashlimit-above", f"{rate}/sec",
                           "--hashlimit-burst", str(max(rate * 2, 1)), "--hashlimit-mode", "srcip",
                           "--hashlimit-name", "nd" + rule.short_id(), "-j", "DROP"]
        return base + ["-j", "DROP"]

    def _install_rule(self, rule):
        if rule.needs_ct:
            return True
        pname = PROTO_NUM_TO_IPT.get(rule.proto)
        tools = self._tools()
        if rule.proto == 1:
            fams = [("iptables", False)]
        elif rule.proto == 58:
            fams = [("ip6tables", True)] if "ip6tables" in tools else []
        elif rule.src_net is not None or rule.dst_net is not None:
            v6 = (rule.src_net or rule.dst_net).version == 6
            fams = [("ip6tables", True)] if v6 else [("iptables", False)]
        else:
            fams = [(t, t == "ip6tables") for t in tools]
        ok = True
        for ipt, v6 in fams:
            if rule.frag and v6:
                continue
            ok = self._add(ipt, self._rule_args(rule, pname, v6)) and ok
        return ok

    def _install_filter(self, rule):
        if rule.needs_ct:
            log.info("%s needs connection tracking; handled by the INVALID rule when "
                     "[conntrack] drop_invalid is on", rule.name)
            return False
        return self._install_rule(rule)

    def sync_filters(self):
        with self.lock:
            for ipt in self._tools():
                self._run([ipt, "-t", "raw", "-F", self.CHAIN])
            if self.use_ipset:
                self._load_drop_sets()
            self._add_base_rules()
            for rule, _exp in self.active_filters.values():
                self._install_rule(rule)
            return True

    def dropped_packets(self):
        total, seen = 0, False
        for ipt in self._tools():
            for chain in (self.CHAIN, self.SRC):
                rc, out, _ = self._run([ipt, "-t", "raw", "-L", chain, "-nvx"])
                if rc != 0:
                    continue
                seen = True
                for line in out.splitlines():
                    parts = line.split()
                    if len(parts) >= 3 and parts[0].isdigit() and parts[2] == "DROP":
                        total += int(parts[0])
        return total if seen else None

    def _cleanup_blocked(self, now):
        if self.use_ipset:
            return
        for ip in [ip for ip, exp in self.blocked.items() if exp <= now]:
            self.unblock_src(ip)

    def teardown(self):
        if self.dry:
            return
        for ipt in self._tools():
            for ch in (self.SRC, self.CHAIN):
                for h in self._hooks() + [[]]:
                    while self._run([ipt, "-t", "raw", "-D", "PREROUTING"] + h + ["-j", ch])[0] == 0:
                        pass
                self._run([ipt, "-t", "raw", "-F", ch])
                self._run([ipt, "-t", "raw", "-X", ch])
        self._sync_conntrack_off()

    def _sync_conntrack_off(self):
        spec = ["-m", "conntrack", "--ctstate", "INVALID", "-m", "comment",
                "--comment", "netdeflect", "-j", "DROP"]
        for ipt in self._tools():
            self._run([ipt, "-t", "mangle", "-D", "PREROUTING"] + spec)


# ---- blackhole (source-only null routes) ----------------------------------- #

class BlackholeFirewall(BaseFirewall):
    RT_PROTO = "254"  # our routes are tagged so cleanup never touches yours

    def setup(self):
        self._load_state()
        val = _read_int("/proc/sys/net/ipv4/conf/all/rp_filter")
        if val == 0:
            log.warning("blackhole backend: rp_filter=0, so null routes stop replies "
                        "but not inbound packets. Set net.ipv4.conf.all.rp_filter=2, "
                        "or use the nftables backend.")
        if self.cfg.get("services"):
            log.warning("blackhole backend cannot protect service ports or drop "
                        "patterns; use nftables for that.")
        return True

    def unsupported_fields(self, rule):
        return ["pattern rules (blackhole only null-routes sources)"]

    def block_many(self, ips, timeout=None):
        to = self.timeout if timeout is None else timeout
        exp = (time.time() + to) if to else float("inf")
        new = [ip for ip in ips if ip not in self.blocked]
        conflicts = self._route_conflicts(new) if new else set()
        apply = [ip for ip in new if _canon(ip) not in conflicts]
        for ip in new:
            if _canon(ip) in conflicts:
                log.warning("Not null-routing %s: a route for it already exists that "
                            "NetDeflect did not create", ip)
        if apply:
            batch = "\n".join(f"route replace blackhole {ip} proto {self.RT_PROTO}" for ip in apply)
            self._run(["ip", "-force", "-batch", "-"], input_text=batch + "\n")
        done = []
        for ip in ips:
            if ip in self.blocked or ip in apply:
                self.blocked[ip] = max(self.blocked.get(ip, 0), exp)
                done.append(ip)
        self._save_state()
        return done

    def _route_conflicts(self, items):
        """Addresses among items that already have a route we did not create
        (e.g. your own on-link subnet), found with one listing per family
        instead of one `ip route show` per address."""
        out = set()
        wanted = {_canon(i) for i in items}
        for fam in ("-4", "-6"):
            if not any((":" in i) == (fam == "-6") for i in wanted):
                continue
            rc, text, _ = self._run(["ip", fam, "-j", "route", "show", "table", "main"])
            if rc != 0 or not text.strip():
                continue
            try:
                routes = json.loads(text)
            except json.JSONDecodeError:
                continue
            for r in routes:
                dst = _canon(str(r.get("dst", "")))
                if dst in wanted and r.get("type") != "blackhole" \
                        and str(r.get("protocol")) != self.RT_PROTO:
                    out.add(dst)
        return out

    def _route_conflict(self, ip):
        return _canon(ip) in self._route_conflicts([ip])

    def block_net_many(self, nets, timeout=None):
        return self.block_many(nets, timeout)

    def block_src(self, ip, timeout=None):
        return bool(self.block_many([ip], timeout))

    def block_net(self, net, timeout=None):
        return bool(self.block_many([net], timeout))

    def unblock_src(self, ip):
        self._run(["ip", "route", "del", "blackhole", ip, "proto", self.RT_PROTO])
        self.blocked.pop(ip, None)
        self._save_state()
        return True

    def list_blocks(self):
        if not self.blocked:
            self._load_state()
        return list(self.blocked)

    def sync_filters(self):
        return True

    def _cleanup_blocked(self, now):
        expired = [ip for ip, exp in self.blocked.items() if exp <= now]
        if expired:
            batch = "\n".join(f"route del blackhole {ip} proto {self.RT_PROTO}" for ip in expired)
            self._run(["ip", "-force", "-batch", "-"], input_text=batch + "\n")
            for ip in expired:
                self.blocked.pop(ip, None)
            self._save_state()

    def teardown(self):
        """Remove our null routes when NetDeflect stops, like every other
        backend (systemd's ExecStopPost does the same if we are killed)."""
        if self.dry:
            return
        if not self.blocked:
            self._load_state()
        if self.blocked:
            batch = "\n".join(f"route del blackhole {ip} proto {self.RT_PROTO}" for ip in self.blocked)
            self._run(["ip", "-force", "-batch", "-"], input_text=batch + "\n")
        self.blocked = {}
        try:
            os.remove(STATE_FILE)
        except OSError:
            pass

    def _save_state(self):
        try:
            data = {ip: (exp if exp != float("inf") else None) for ip, exp in self.blocked.items()}
            tmp = STATE_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump({"blocked": data}, fh)
            os.replace(tmp, STATE_FILE)
        except OSError:
            pass

    def _load_state(self):
        try:
            if os.path.exists(STATE_FILE):
                with open(STATE_FILE, encoding="utf-8") as fh:
                    raw = json.load(fh).get("blocked", {})
                self.blocked = {ip: (float("inf") if exp is None else exp) for ip, exp in raw.items()}
        except (OSError, json.JSONDecodeError):
            pass


# ---- BGP / out-of-band (no local drops) ------------------------------------ #

class BgpFirewall(BaseFirewall):
    """Out-of-band mitigation. Installs NO local kernel rules. Instead it asks the
    upstream network to drop the attacker prefixes over BGP (RTBH / FlowSpec via
    the Escalator) and, if configured, pushes them to an external firewall or
    scrubbing API. This is the backend for sFlow/NetFlow deployments and 10G/100G
    links, where the traffic never passes through this host so there is nothing to
    drop here. If NetDeflect stops, the router keeps forwarding: the link never
    fails closed the way an inline appliance does."""

    supports_payload_match = False

    def __init__(self, cfg, escalator=None):
        super().__init__(cfg)
        self.escalator = escalator if escalator is not None else Escalator(cfg)
        if cfg.get("bgp_enabled"):
            self.escalator.enabled = True
        self._api = cfg.get("enable_api_integration")

    def setup(self):
        if not self.cfg.get("bgp_enabled") and not self._api:
            log.warning("bgp backend: no upstream configured (set [escalation] "
                        "bgp_enabled or [external_firewall] enable_api_integration); "
                        "running detect-and-report only.")
        return True

    def healthy(self):
        return True

    def unsupported_fields(self, rule):
        # Upstream RTBH/FlowSpec blocks by address, not by packet byte-pattern.
        return ["pattern rules (the bgp backend blocks addresses upstream, not patterns)"]

    def _announce_all(self, items, timeout=None):
        to = self.timeout if timeout is None else timeout
        exp = (time.time() + to) if to else float("inf")
        done = []
        fresh = {}
        for it in items:
            if it in self.blocked:
                self.blocked[it] = max(self.blocked[it], exp)
                done.append(it)
                continue
            prefix = it if "/" in it else self.escalator._prefix_for(it)
            if prefix:
                fresh[it] = prefix
        announced = set()
        if fresh and self.cfg.get("bgp_enabled"):
            # one pipe write for the whole batch; capped by max_announced_prefixes
            announced = set(self.escalator.announce_many(list(fresh.values())))
        # Record the block only if something upstream actually acted (BGP
        # announced it, or an external API is configured to take it). With no
        # upstream, nothing happened, so do not claim a block that is not real.
        for it, prefix in fresh.items():
            if prefix in announced or self._api:
                self.blocked[it] = exp
                done.append(it)
        return done

    def block_many(self, ips, timeout=None):
        # The external API send is driven by run_cycle for result.blocked_ips, so
        # here we only announce upstream and record the block.
        return self._announce_all(ips, timeout)

    def block_net_many(self, nets, timeout=None):
        return self._announce_all(nets, timeout)

    def block_src(self, ip, timeout=None):
        return bool(self.block_many([ip], timeout))

    def block_net(self, net, timeout=None):
        return bool(self.block_net_many([net], timeout))

    def unblock_src(self, ip):
        prefix = ip if "/" in ip else self.escalator._prefix_for(ip)
        if prefix in self.escalator.announced:
            self.escalator.announced[prefix] = 0
            self.escalator.cleanup()
        self.blocked.pop(ip, None)
        return True

    def list_blocks(self):
        return list(self.blocked)

    def sync_filters(self):
        return True

    def _cleanup_blocked(self, now):
        for ip in [ip for ip, exp in self.blocked.items() if exp <= now]:
            self.unblock_src(ip)

    def teardown(self):
        self.escalator.withdraw_all()


def make_firewall(cfg):
    system = cfg["firewall_system"]
    if system == "bgp":
        return BgpFirewall(cfg)
    if system in ("nftables", "xdp"):
        if not shutil.which("nft"):
            log.error("nft not found: install nftables (apt install nftables) or "
                      "set firewall_system to ipset/iptables/blackhole")
            sys.exit(1)
        return XdpFirewall(cfg) if system == "xdp" else NftFirewall(cfg)
    if system in ("ipset", "iptables"):
        if not shutil.which("iptables"):
            log.error("iptables not found; install it or choose another backend")
            sys.exit(1)
        return IptablesFirewall(cfg, use_ipset=(system == "ipset"))
    if system == "blackhole":
        if not shutil.which("ip"):
            log.error("iproute2 (ip) not found; blackhole backend unavailable")
            sys.exit(1)
        return BlackholeFirewall(cfg)
    log.error("Unknown firewall_system: %s", system)
    sys.exit(1)


# --------------------------------------------------------------------------- #
#  On-demand artefacts (systemd unit, uninstall) and config-free teardown
# --------------------------------------------------------------------------- #
#  These are generated when you ask for them (install.sh, --install-service,
#  --write-uninstall), not shipped in the repo, so a checkout has only the
#  program, the signatures and the installer. settings.ini and
#  notification_template.json are likewise written on first run.

SERVICE_UNIT = """\
[Unit]
Description=NetDeflect DDoS protection
Documentation=https://github.com/0vm/NetDeflect
After=network-online.target nftables.service docker.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory={workdir}
ExecStart={python} {script} --config {config}
# systemctl reload netdeflect re-reads settings.ini and methods.json
ExecReload=/bin/kill -HUP $MAINPID
# Removes NetDeflect's firewall rules if it ever exits without cleaning up
ExecStopPost=-{python} {script} --config {config} --teardown
Restart=on-failure
RestartSec=5
Nice=-5
User=root
ProtectHome=read-only
ProtectSystem=full

[Install]
WantedBy=multi-user.target
"""

# A thin wrapper some operators like to keep next to the program. It just calls
# the in-program teardown, which removes every object across all backends.
UNINSTALL_SCRIPT = """\
#!/usr/bin/env bash
# Remove every firewall object NetDeflect may have created, across all backends
# (its nft table, NETDEFLECT iptables chains, nd_* ipsets, proto-254 blackhole
# routes and xdp-filter on the interfaces it recorded). Only NetDeflect's own
# objects are touched. Safe to run at any time.
cd "$(dirname "$0")" 2>/dev/null || true
exec {python} "{script}" --teardown
"""


def _run_quiet(cmd, input_text=None):
    try:
        return subprocess.run(cmd, input=input_text, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True, timeout=30)
    except Exception:  # noqa: BLE001
        class _R:
            returncode, stdout, stderr = 1, "", ""
        return _R()


def teardown_all():
    """Remove every firewall object NetDeflect may have created, without needing
    a valid settings.ini. This is what the systemd unit runs on stop and what
    `--teardown` does, replacing the old uninstall_rules.sh."""
    removed = []
    # XDP: unload xdp-filter from the interfaces a run recorded.
    state = os.path.join(DATA_DIR, "xdp_interfaces.json")
    if shutil.which("xdp-filter") and os.path.exists(state):
        try:
            with open(state, encoding="utf-8") as fh:
                ifaces = json.load(fh).get("interfaces", [])
        except (OSError, ValueError):
            ifaces = []
        for iface in ifaces:
            if isinstance(iface, str) and iface.replace("-", "").replace("_", "").replace(".", "").replace("@", "").isalnum():
                if _run_quiet(["xdp-filter", "unload", iface]).returncode == 0:
                    removed.append(f"xdp-filter on {iface}")
    try:
        os.remove(state)
    except OSError:
        pass
    # nftables
    if shutil.which("nft"):
        if _run_quiet(["nft", "delete", "table", "inet", "netdeflect"]).returncode == 0:
            removed.append("nft table inet netdeflect")
        _run_quiet(["nft", "delete", "table", "netdev", "netdeflect_ingress"])
    # iptables / ip6tables: scoped PREROUTING jumps, chains, and the INVALID rule
    for ipt in ("iptables", "ip6tables"):
        if not shutil.which(ipt):
            continue
        listing = _run_quiet([ipt, "-t", "raw", "-S", "PREROUTING"]).stdout
        for line in listing.splitlines():
            if re.search(r"-j NETDEFLECT(_SRC)?$", line):
                _run_quiet([ipt, "-t", "raw"] + line.replace("-A ", "-D ", 1).split())
        for ch in ("NETDEFLECT", "NETDEFLECT_SRC"):
            _run_quiet([ipt, "-t", "raw", "-F", ch])
            if _run_quiet([ipt, "-t", "raw", "-X", ch]).returncode == 0:
                removed.append(f"{ipt} chain {ch}")
        _run_quiet([ipt, "-t", "mangle", "-D", "PREROUTING", "-m", "conntrack",
                    "--ctstate", "INVALID", "-m", "comment", "--comment", "netdeflect",
                    "-j", "DROP"])
    # ipset
    if shutil.which("ipset"):
        for s in ("nd_blocked4", "nd_blocked6", "nd_blockednet4", "nd_blockednet6",
                  "nd_drop4", "nd_drop6", "nd_known4", "nd_known6"):
            if _run_quiet(["ipset", "destroy", s]).returncode == 0:
                removed.append(f"ipset {s}")
    # blackhole routes we tagged (proto 254)
    if shutil.which("ip"):
        for fam in ("-4", "-6"):
            out = _run_quiet(["ip", fam, "route", "show", "type", "blackhole", "proto", "254"]).stdout
            batch = "\n".join(f"route del blackhole {ln.split()[1]} proto 254"
                              for ln in out.splitlines() if len(ln.split()) >= 2)
            if batch:
                _run_quiet(["ip", "-force", "-batch", "-"], input_text=batch + "\n")
                removed.append(f"{len(batch.splitlines())} blackhole route(s) ({fam})")
    for leftover in (STATE_FILE,):
        try:
            os.remove(leftover)
        except OSError:
            pass
    return removed


def write_uninstall_script(path=None):
    path = path or os.path.join(BASE_DIR, "uninstall_rules.sh")
    script = os.path.abspath(__file__)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(UNINSTALL_SCRIPT.format(python=sys.executable, script=script))
    try:
        os.chmod(path, 0o755)
    except OSError:
        pass
    return path


def install_service(config_path, start=True):
    """Write and enable the systemd unit, generated for this install's paths.
    Also drops an uninstall_rules.sh next to the program for manual use."""
    if os.name != "posix" or not shutil.which("systemctl"):
        print("systemd not found; run NetDeflect directly with: "
              f"{sys.executable} {os.path.abspath(__file__)}")
        return False
    script = os.path.abspath(__file__)
    config = os.path.abspath(config_path)
    if not os.path.exists(config):
        write_default_config(config)
        print(f"Wrote default {os.path.basename(config)} (edit it, then: systemctl reload netdeflect).")
    unit = SERVICE_UNIT.format(python=sys.executable, script=script,
                               workdir=os.path.dirname(script), config=config)
    unit_path = "/etc/systemd/system/netdeflect.service"
    try:
        with open(unit_path, "w", encoding="utf-8") as fh:
            fh.write(unit)
    except OSError as exc:
        print(f"Could not write {unit_path}: {exc} (are you root?)", file=sys.stderr)
        return False
    write_uninstall_script()
    _run_quiet(["systemctl", "daemon-reload"])
    if start:
        _run_quiet(["systemctl", "enable", "--now", "netdeflect"])
        print("NetDeflect service installed and started.")
        print("  Status : systemctl status netdeflect")
        print("  Logs   : journalctl -u netdeflect -f")
        print("  Config : edit", config, "then: systemctl reload netdeflect")
    else:
        _run_quiet(["systemctl", "enable", "netdeflect"])
        print("NetDeflect service installed (enabled on boot). Start with: systemctl start netdeflect")
    return True


# --------------------------------------------------------------------------- #
#  Mitigation planner
# --------------------------------------------------------------------------- #

def select_source_targets(src_counter, whitelist, cfg):
    """Decide which source IPs (and aggregated /24 or /64) to block, skipping
    protected addresses."""
    ips, nets = [], []
    by_subnet = defaultdict(list)
    # heaviest first, so a bounded consumer (the XDP map, an upstream prefix
    # limit) gets the sources that matter most
    ordered = [ip for ip, _ in src_counter.most_common()] if hasattr(src_counter, "most_common") \
        else list(src_counter)
    for ip in ordered:
        if whitelist.is_protected(ip):
            continue
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        plen = 24 if addr.version == 4 else 64
        net = str(ipaddress.ip_network(f"{ip}/{plen}", strict=False))
        by_subnet[net].append(ip)
    agg = cfg["subnet_aggregate_count"]
    for net, members in by_subnet.items():
        if agg and len(members) >= agg:
            nets.append(net)
        else:
            ips.extend(members)
    return ips, nets


class MitigationResult:
    def __init__(self):
        self.filters_applied = []
        self.blocked_ips = []
        self.blocked_nets = []
        self.reflectors_blocked = []
        self.spoofed_spared = []
        self.autodetected = []
        self.notes = []
        self.escalated = []

    def dedup(self):
        self.blocked_ips = sorted(set(self.blocked_ips))
        self.blocked_nets = sorted(set(self.blocked_nets))
        self.reflectors_blocked = sorted(set(self.reflectors_blocked))


def plan_and_mitigate(fw, classification, cfg, whitelist):
    res = MitigationResult()
    tunnel = {p.lower() for p in cfg["protocols_in_use"]}

    def _apply(sig, pct):
        if fw.apply_filter(FilterRule(sig, cfg)):
            res.filters_applied.append(f"{sig.name} ({pct:.1f}%)")
            log.info("Mitigating %s (%.1f%% of traffic, %s)", sig.name, pct, sig.strategy)
            return True
        res.notes.append(f"{sig.name}: detected, not enforceable on this backend (report only)")
        return False

    def _block(ips, nets, timeout=None):
        done_n = fw.block_net_many(nets, timeout) if nets else []
        done_i = fw.block_many(ips, timeout) if ips else []
        res.blocked_nets += done_n
        res.blocked_ips += done_i
        return done_i, done_n

    for sig, count, pct in classification.matched:
        strat = sig.strategy
        srcs = classification.src_by_sig.get(sig.uid, Counter())
        if strat in ("filter", "ratelimit", "syn", "conn_limit"):
            if sig.category == "proto_flood" and (proto_name(sig.proto) in tunnel
                                                  or str(sig.proto) in tunnel):
                res.notes.append(f"{sig.name}: skipped ({proto_name(sig.proto)} is in protocols_in_use)")
                continue
            _apply(sig, pct)
            if sig.real_source and cfg["block_reflectors"]:
                # Reflection/amplification sources are real servers. A big attack
                # uses thousands of them, each a tiny share of the sample, so by
                # default EVERY reflector seen is null-routed (whitelist still wins).
                thresh = cfg["reflector_block_percent"]
                total = max(classification.total, 1)
                cand = Counter({ip: c for ip, c in srcs.items()
                                if c >= cfg["reflector_min_packets"]
                                and 100.0 * c / total >= thresh})
                cap = cfg["max_reflector_blocks"]
                if cap and len(cand) > cap:
                    res.notes.append(f"{sig.name}: {len(cand)} reflectors seen, blocking "
                                     f"the top {cap} (max_reflector_blocks)")
                    cand = Counter(dict(cand.most_common(cap)))
                ips, nets = select_source_targets(cand, whitelist, cfg)
                done_i, done_n = _block(ips, nets)
                res.reflectors_blocked += done_i
                if done_i or done_n:
                    log.info("Null-routed %d reflector IPs and %d subnets for %s",
                             len(done_i), len(done_n), sig.name)
            elif not sig.real_source:
                res.spoofed_spared.append(sig.name)
                if (cfg["block_flood_contributors"] and sig.category in
                        ("udp_flood", "tcp_flood", "icmp_flood", "proto_flood",
                         "fragment_flood", "tcp_flag")):
                    contributors = _few_stable_sources(srcs, classification, cfg, whitelist)
                    if contributors:
                        _block(contributors, [], cfg["flood_contributor_block_time"])
                        log.info("block_flood_contributors: blocked %d stable sources of %s",
                                 len(contributors), sig.name)

        elif strat == "block_src":
            ips, nets = select_source_targets(srcs, whitelist, cfg)
            done_i, done_n = _block(ips, nets, sig.block_time)
            log.info("Blocked %d source IPs and %d subnets for %s",
                     len(done_i), len(done_n), sig.name)

        elif strat == "report":
            if sig.category in ("stateful_flood", "ack_flood"):
                if cfg.get("enable_connection_tracking") and cfg.get("drop_invalid"):
                    res.notes.append(f"{sig.name}: out-of-state packets dropped by the "
                                     f"connection-tracking INVALID rule")
                else:
                    res.notes.append(f"{sig.name}: out-of-state flood; enable [conntrack] "
                                     f"drop_invalid to drop these")
            else:
                res.notes.append(f"{sig.name}: report only")

    if not classification.matched and cfg["enable_fallback_blocking"]:
        res.notes.append("Unclassified attack: fallback blocking of top sources")
        top = [ip for ip, c, pct in classification.top_sources
               if pct >= cfg["contributor_threshold"] and not whitelist.is_protected(ip)]
        if top:
            _block(top, [])
    elif not classification.matched:
        res.notes.append("Unclassified attack: no automatic action. Review the capture "
                         "and consider upstream mitigation.")

    res.dedup()
    return res


def _few_stable_sources(srcs, classification, cfg, whitelist):
    """Sources of a flood that look real rather than spoofed: there are only a
    few of them and each sends a single, stable TTL. A spoofed flood presents
    many forged, randomised sources, so this guard avoids blackholing them."""
    cand = [ip for ip in srcs if not whitelist.is_protected(ip)]
    if not cand or len(cand) > cfg["flood_contributor_max_sources"]:
        return []
    total = max(classification.total, 1)
    out = []
    for ip in cand:
        pct = 100.0 * srcs[ip] / total
        if pct < cfg["flood_contributor_percent"]:
            continue
        if classification.src_ttl.get(ip) is None:  # varied/unknown TTL -> likely spoofed
            continue
        out.append(ip)
    return out


# --------------------------------------------------------------------------- #
#  Effectiveness + saturation
# --------------------------------------------------------------------------- #

def flow_effectiveness(fw, cfg, flow_pps):
    """Out-of-band 'effectiveness' for flow (sFlow/NetFlow) mode: there are no
    local drop counters because the traffic never passes through this host, so we
    report what was asked of the upstream instead."""
    announced = len(getattr(getattr(fw, "escalator", None), "announced", {}) or {})
    blocked = fw.count_blocks()
    if announced or blocked:
        verdict = "upstream mitigation active"
    elif cfg.get("bgp_enabled") or cfg.get("enable_api_integration"):
        verdict = "detected; awaiting upstream action"
    else:
        verdict = "detected; no upstream mitigation configured"
    return {"dropped_pps": None, "passed_pps": flow_pps, "nic_pps": flow_pps,
            "nic_drop_pps": None, "softnet_pps": None, "ct_pct": None,
            "saturated": False, "verdict": verdict,
            "detail": f"out-of-band: {announced} prefix(es) announced upstream, "
                      f"{blocked} address(es) blocked"}


def measure_effectiveness(fw, interfaces, cfg, window=2.0):
    import psutil
    iface = cfg["network_interface"]
    d0 = fw.dropped_packets()
    n0 = network_sample(iface)
    nic0 = nic_drop_counters(interfaces)
    sn0, _ = softnet_drops()
    time.sleep(window)
    d1 = fw.dropped_packets()
    n1 = network_sample(iface)
    nic1 = nic_drop_counters(interfaces)
    sn1, _ = softnet_drops()

    nic_pps = int((n1[0] - n0[0]) / window) if (n0 and n1) else 0
    nic_drop_pps = (int((nic1 - nic0) / window) if (nic0 is not None and nic1 is not None) else None)
    softnet_pps = (int((sn1 - sn0) / window) if (sn0 is not None and sn1 is not None) else None)
    ctc, ctmax = conntrack_usage()
    ct_pct = (100.0 * ctc / ctmax) if (ctc and ctmax) else None

    saturated = bool((nic_drop_pps and nic_drop_pps > 0) or (softnet_pps and softnet_pps > 0))

    if d0 is None or d1 is None:
        return {"dropped_pps": None, "passed_pps": nic_pps, "nic_pps": nic_pps,
                "nic_drop_pps": nic_drop_pps, "softnet_pps": softnet_pps,
                "ct_pct": ct_pct, "saturated": saturated, "verdict": "unknown",
                "detail": "backend has no drop counters; NIC inbound only"}

    # counters restart when the ruleset is rebuilt; never report a negative rate
    dropped_pps = max(int((d1 - d0) / window), 0)
    passed_pps = max(nic_pps - dropped_pps, 0)
    if saturated:
        verdict = "host saturated - escalate upstream"
    elif nic_pps == 0:
        verdict = "idle"
    elif dropped_pps == 0:
        verdict = "no drops (sources may be spoofed/upstream)"
    elif dropped_pps >= nic_pps * 0.7:
        verdict = "mitigated"
    elif dropped_pps >= nic_pps * 0.2:
        verdict = "partially mitigated"
    else:
        verdict = "ongoing"
    return {"dropped_pps": dropped_pps, "passed_pps": passed_pps, "nic_pps": nic_pps,
            "nic_drop_pps": nic_drop_pps, "softnet_pps": softnet_pps, "ct_pct": ct_pct,
            "saturated": saturated, "verdict": verdict, "detail": ""}


# --------------------------------------------------------------------------- #
#  Auto-detection of unknown patterns (bounded, safe)
# --------------------------------------------------------------------------- #

NGRAM = 4  # bytes for payload-fragment detection


def _dominant_ngram(pkts, srcs, min_sources, exclude=()):
    gram_sources = defaultdict(set)
    per_source = defaultdict(int)
    for pkt in pkts:
        src = pkt.get("src")
        payload = pkt.get("payload")
        if not src or src not in srcs or not payload:
            continue
        if per_source[src] > 40:
            continue
        per_source[src] += 1
        seen = set()
        for i in range(min(len(payload) - NGRAM + 1, 48)):
            gram = payload[i:i + NGRAM]
            if gram not in seen:
                seen.add(gram)
                gram_sources[gram].add(src)
    best = None
    for gram, s in gram_sources.items():
        if len(set(gram)) <= 1 or gram in exclude:
            continue
        if len(s) >= min_sources and (best is None or len(s) > len(best[1])):
            best = (gram, s)
    return best[0] if best else None


def _repeated_byte(payloads):
    byte_hits = Counter()
    checked = 0
    for payload in payloads:
        if not payload or len(payload) < 8:
            continue
        checked += 1
        b0 = payload[:1]
        if payload == b0 * len(payload):
            byte_hits[b0] += 1
        if checked > 500:
            break
    if not byte_hits:
        return None
    byte, hits = byte_hits.most_common(1)[0]
    if checked and hits / checked >= 0.7:
        return byte * 8
    return None


def _dominant_length(pkts):
    lengths = Counter(p.get("len", 0) for p in pkts)
    if not lengths:
        return None, 0.0
    length, hits = lengths.most_common(1)[0]
    return length, hits / len(pkts)


def _dominant(values, floor):
    """The most common non-None value and its share, or (None, share) if that
    share is below `floor`. A value that dominates a field most traffic would vary
    (source port, TTL, window, flags) is an attack fingerprint."""
    vals = [v for v in values if v is not None]
    if not vals:
        return None, 0.0
    val, hits = Counter(vals).most_common(1)[0]
    frac = hits / len(vals)
    return (val if frac >= floor else None), frac


def autodetect_patterns(packets, classification, whitelist, cfg, known=None, baseline=None):
    """Learn an attack's fingerprint when no built-in signature hard-drops it.

    Looks at the whole packet, not just the payload: source port, TTL, TCP window,
    DSCP, TCP flags, length and payload fragments. It builds the MOST SPECIFIC drop
    rule that still covers the attack (for example "udp dport 9000 sport 6666
    ttl 111"), so normal traffic on the same port, with a different TTL or window,
    is never caught. A pattern becomes an enforced DROP only when it is a confirmed
    bad actor: it dominates the attack across many sources (or a few heavy, stable
    ones), it holds header fields that legitimate clients would vary, and it does
    not match your learned real clients or peacetime baseline."""
    if not cfg["enable_pattern_detection"]:
        return []
    known = known or set()
    baseline = baseline or {}
    total = classification.total
    if total == 0:
        return []
    min_sources = cfg["autodetect_min_sources"]
    min_pct = cfg["autodetect_min_percent"]
    heavy_pct = cfg["autodetect_heavy_source_percent"]
    marker = max(0.5, min(1.0, cfg.get("autodetect_marker_pct", 85) / 100.0))
    skip_ports = set(cfg.get("bypass_ports", set()))

    groups = defaultdict(list)
    for pkt in packets:
        proto, dport = pkt.get("proto"), pkt.get("dport")
        if proto not in (6, 17) or dport in skip_ports or pkt.get("src") in known:
            continue
        groups[(proto, dport)].append(pkt)

    detections = []
    for (proto, dport), pkts in groups.items():
        coverage = 100.0 * len(pkts) / total
        if coverage < min_pct:
            continue
        srcs = {p["src"] for p in pkts if p.get("src") and not whitelist.is_protected(p["src"])}
        src_counts = Counter(p["src"] for p in pkts if p.get("src"))
        heavy_srcs = {ip for ip, c in src_counts.items()
                      if 100.0 * c / total >= heavy_pct and not whitelist.is_protected(ip)}
        few_ok = 1 <= len(heavy_srcs) < min_sources
        if len(srcs) < min_sources and not few_ok:
            continue
        pname = "tcp" if proto == 6 else "udp"
        eff_srcs = srcs if len(srcs) >= min_sources else heavy_srcs
        payloads = [p["payload"] for p in pkts if p.get("payload")]
        # If the dominant payload here is one your learned real clients send on
        # this port, it is legitimate traffic: never fingerprint it (not by payload
        # and not by its header fields either).
        if baseline.get(dport):
            pref, _ = _dominant([p[:4] for p in payloads if len(p) >= 4], marker)
            if pref is not None and pref in baseline[dport]:
                continue

        # Header-field fingerprint: values this attack holds constant that normal
        # traffic would vary across clients.
        # One flow from one host trivially has a single source port, TTL and set of
        # flags; that is not an attack fingerprint (a big upload or backup looks
        # exactly like that). Only learn from traffic spread over several sources,
        # and only count a header value that several DISTINCT sources share.
        # Single heavy senders stay with the opt-in contributor/fallback blocking.
        if len(eff_srcs) < 2:
            continue
        need_srcs = max(2, (len(eff_srcs) + 1) // 2)

        def shared(key, val):
            return len({p.get("src") for p in pkts
                        if p.get(key) == val and p.get("src") in eff_srcs}) >= need_srcs

        markers, reason = {}, []
        sport, _ = _dominant([p.get("sport") for p in pkts], marker)
        if sport is not None and shared("sport", sport):
            markers["sport"] = sport; reason.append(f"sport {sport}")
        ttl, _ = _dominant([p.get("ttl") for p in pkts], marker)
        if ttl is not None and shared("ttl", ttl):
            markers["ttl"] = ttl; reason.append(f"ttl {ttl}")
        win, _ = _dominant([p.get("tcp_window") for p in pkts], marker)
        if win and shared("tcp_window", win):
            markers["tcp_window"] = win; reason.append(f"window {win}")
        tos, _ = _dominant([p.get("tos") for p in pkts], marker)
        if tos and shared("tos", tos):
            markers["tos"] = tos; reason.append(f"dscp {tos >> 2}")
        if proto == 6:
            flg, _ = _dominant([p.get("flags") for p in pkts], marker)
            # ACK / ACK+PSH / ACK+FIN are what every established connection sends;
            # they say nothing about an attack, so never key on them.
            if flg is not None and (flg & 0x3F) not in (0x10, 0x18, 0x11, 0x19) \
                    and shared("flags", flg):
                names = flag_value_to_names(flg)
                if names:
                    markers["tcp_flags"] = ",".join(names)
                    reason.append("flags " + "|".join(names))
        gram = _dominant_ngram(pkts, eff_srcs, min(min_sources, len(eff_srcs)) if eff_srcs else min_sources,
                               exclude=baseline.get(dport, ()))
        rbyte = _repeated_byte(payloads)
        if gram:
            markers["payload_hex"], markers["payload_offset"] = gram.hex(), 0
            reason.append(f"payload {gram.hex()}")
        elif rbyte and len({p.get("src") for p in pkts if p.get("src") in eff_srcs
                            and (p.get("payload") or b"")[:1] == rbyte[:1]
                            and p["payload"] == rbyte[:1] * len(p["payload"])}) >= need_srcs:
            markers["payload_hex"], markers["payload_offset"] = rbyte.hex(), 0
            reason.append(f"repeated 0x{rbyte.hex()[:2]}")

        # Fields normal traffic varies -> each dominant one is a real discriminator.
        discriminators = sum(1 for k in ("sport", "ttl", "tcp_window", "tos",
                                         "tcp_flags", "payload_hex") if k in markers)
        length, lenfrac = _dominant_length(pkts)
        fixed_len = length is not None and lenfrac >= marker and shared("len", length)
        if fixed_len and (discriminators or lenfrac >= 0.95):
            markers["min_len"] = markers["max_len"] = length
            reason.append(f"len {length}")
        if discriminators == 0 and not fixed_len:
            continue   # nothing specific enough to key on; stays monitoring-only

        confidence = "high" if (discriminators >= 2 or "payload_hex" in markers
                                or (discriminators >= 1 and fixed_len)) else "medium"
        # Many spoofed sources -> spoof-safe pattern drop. A few heavy, stable
        # sources are a confirmed bad actor -> block them.
        cat = ("botnet" if (few_ok and (discriminators or fixed_len))
               else ("udp_flood" if proto == 17 else "tcp_flood"))
        tag = "".join(ch for ch in "_".join(reason) if ch.isalnum() or ch == "_")[:40]
        det = {"type": "composite", "label": f"Auto_{pname}{dport}_{tag}",
               "category": cat, "proto": pname, "dport": dport,
               "coverage_pct": round(coverage, 1), "confidence": confidence,
               "source_ips": sorted(eff_srcs), "block_time": cfg["autodetect_block_time"],
               "reason": ", ".join(reason)}
        det.update(markers)
        detections.append(det)
    detections.sort(key=lambda d: (d["confidence"] == "high", d["coverage_pct"]), reverse=True)
    return detections[:4]


def _autodetect_key(entry):
    return (entry.get("type"), entry.get("payload_hex"), entry.get("proto"),
            entry.get("dport"), entry.get("sport"), entry.get("ttl"),
            entry.get("tcp_window"), entry.get("tcp_flags"), entry.get("min_len"))


def save_autodetected(entry):
    try:
        existing = []
        if os.path.exists(AUTODETECT_FILE):
            with open(AUTODETECT_FILE, encoding="utf-8") as fh:
                existing = json.load(fh)
        key = _autodetect_key(entry)
        for row in existing:
            if _autodetect_key(row) == key:
                return False
        entry = dict(entry)
        entry["timestamp"] = get_timestamp()
        entry["source_ips"] = entry.get("source_ips", [])[:64]
        existing.append(entry)
        existing = existing[-500:]     # keep the newest 500 learned patterns
        tmp = AUTODETECT_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(existing, fh, indent=2)
        os.replace(tmp, AUTODETECT_FILE)
        return True
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("Could not save auto-detected pattern: %s", exc)
        return False


# --------------------------------------------------------------------------- #
#  pcap retention
# --------------------------------------------------------------------------- #

def prune_dir(path, suffixes, max_files):
    """Keep only the newest max_files files with these suffixes in path."""
    if not max_files:
        return 0
    try:
        files = [os.path.join(path, f) for f in os.listdir(path) if f.endswith(suffixes)]
    except OSError:
        return 0
    if len(files) <= max_files:
        return 0
    files.sort(key=lambda p: os.path.getmtime(p))
    removed = 0
    for p in files[:len(files) - max_files]:
        try:
            os.remove(p)
            removed += 1
        except OSError:
            pass
    return removed


def prune_pcaps(max_files):
    if not max_files:
        return 0
    try:
        files = [(os.path.join(CAPTURE_DIR, f), os.path.getmtime(os.path.join(CAPTURE_DIR, f)))
                 for f in os.listdir(CAPTURE_DIR) if f.endswith(".pcap")]
    except OSError:
        return 0
    if len(files) <= max_files:
        return 0
    files.sort(key=lambda x: x[1])
    deleted = 0
    for path, _ in files[:len(files) - max_files]:
        try:
            os.remove(path)
            deleted += 1
        except OSError:
            pass
    return deleted


# --------------------------------------------------------------------------- #
#  Upstream escalation (BGP RTBH / FlowSpec via ExaBGP or a hook script)
# --------------------------------------------------------------------------- #

class Escalator:
    """Announce a blackhole upstream when the local box cannot absorb the attack
    (uplink saturated). The upstream router does the dropping - the only thing
    that helps once the pipe is full. OFF by default.

    Upstream sessions usually carry a max-prefix limit, and going over it tears
    the whole BGP session down, so source-prefix announcements are capped by
    [escalation] max_announced_prefixes. The blackhole of your own attacked
    address (uplink full) and carpet-bombing ranges always go through."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.enabled = cfg["bgp_enabled"]
        self.announced = {}   # prefix -> withdraw-after epoch
        self._cap_noted = False

    def _write_pipe(self, lines):
        """Write commands to ExaBGP's named pipe without ever blocking: opening a
        FIFO for writing waits forever when nothing reads it (ExaBGP stopped or
        restarting), which would freeze the whole daemon mid-attack."""
        pipe = self.cfg["exabgp_command_pipe"]
        try:
            st = os.stat(pipe)
        except OSError:
            log.error("ExaBGP command pipe %s does not exist (is ExaBGP running with "
                      "its API pipe enabled?)", pipe)
            return False
        data = ("\n".join(lines) + "\n").encode()
        try:
            if stat.S_ISFIFO(st.st_mode):
                fd = os.open(pipe, os.O_WRONLY | os.O_NONBLOCK)
            else:
                fd = os.open(pipe, os.O_WRONLY | os.O_APPEND)
        except OSError as exc:
            log.error("ExaBGP is not reading its command pipe %s (%s); nothing was announced",
                      pipe, exc.strerror or exc)
            return False
        try:
            deadline = time.time() + 5
            while data:
                try:
                    n = os.write(fd, data)
                    data = data[n:]
                except BlockingIOError:
                    if time.time() > deadline:
                        log.error("ExaBGP pipe %s stayed full for 5 s; %d bytes not sent",
                                  pipe, len(data))
                        return False
                    time.sleep(0.01)
            return True
        except OSError as exc:
            log.error("Could not write ExaBGP pipe %s: %s", pipe, exc)
            return False
        finally:
            os.close(fd)

    def _hook(self, action, prefix):
        script = self.cfg["escalation_hook_script"]
        if not script:
            return False
        try:
            r = subprocess.run([script, action, prefix, self.cfg["rtbh_community"]],
                               timeout=10, check=False, stdout=subprocess.DEVNULL,
                               stderr=subprocess.PIPE, text=True)
        except Exception as exc:  # noqa: BLE001
            log.error("Escalation hook failed: %s", exc)
            return False
        if r.returncode != 0:
            log.error("Escalation hook %s %s exited with %d: %s", action, prefix,
                      r.returncode, (r.stderr or "").strip()[:200])
            return False
        return True

    def _next_hop(self, prefix):
        nh = self.cfg["rtbh_next_hop"] or "0.0.0.0"
        if ":" in prefix and ":" not in nh:
            nh = "100::1"          # RFC 6666 discard-only prefix
        return nh

    def _prefix_for(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        plen = self.cfg["announce_prefix_len"]
        if addr.version == 6 and plen == 32:
            plen = 128
        return str(ipaddress.ip_network(f"{ip}/{plen}", strict=False))

    def announce(self, ip):
        if not self.enabled:
            return None
        return self.announce_prefix(self._prefix_for(ip), force=True)

    def announce_prefix(self, prefix, force=True):
        done = self.announce_many([prefix], force=force)
        return done[0] if done else None

    def announce_many(self, prefixes, force=False):
        """Announce several prefixes in one go. Returns the ones now announced
        (including any that already were)."""
        if not self.enabled:
            return []
        cap = self.cfg.get("max_announced_prefixes", 500)
        out, todo = [], []
        for p in prefixes:
            if not p:
                continue
            if p in self.announced:
                out.append(p)
                continue
            if not force and cap and len(self.announced) + len(todo) >= cap:
                if not self._cap_noted:
                    log.warning("max_announced_prefixes (%d) reached: further attacker "
                                "prefixes are blocked locally/reported but not announced "
                                "upstream, to stay under your provider's max-prefix limit", cap)
                    self._cap_noted = True
                continue
            todo.append(p)
        if not todo:
            return out
        community = self.cfg["rtbh_community"]
        if self.cfg["bgp_mode"] == "exabgp":
            ok = self._write_pipe([f"announce route {p} next-hop {self._next_hop(p)} "
                                   f"community [{community}]" for p in todo])
            good = todo if ok else []
        else:
            good = [p for p in todo if self._hook("announce", p)]
        due = time.time() + self.cfg["escalation_withdraw_after"]
        for p in good:
            self.announced[p] = due
        if len(good) == 1:
            log.warning("Upstream RTBH announced for %s (community %s)", good[0], community)
        elif good:
            log.warning("Upstream RTBH announced for %d prefixes (community %s), e.g. %s",
                        len(good), community, ", ".join(good[:3]))
        return out + good

    def cleanup(self):
        now = time.time()
        due = [p for p, t in self.announced.items() if now >= t]
        if not due:
            return
        if self.cfg["bgp_mode"] == "exabgp":
            self._write_pipe([f"withdraw route {p} next-hop {self._next_hop(p)}" for p in due])
        else:
            for p in due:
                self._hook("withdraw", p)
        for p in due:
            self.announced.pop(p, None)
        if len(due) == 1:
            log.info("Upstream RTBH withdrawn for %s", due[0])
        else:
            log.info("Upstream RTBH withdrawn for %d prefixes", len(due))
        if len(self.announced) < self.cfg.get("max_announced_prefixes", 500):
            self._cap_noted = False

    def withdraw_all(self):
        for prefix in list(self.announced):
            self.announced[prefix] = 0
        self.cleanup()


# --------------------------------------------------------------------------- #
#  Metrics (Prometheus)
# --------------------------------------------------------------------------- #

class Metrics:
    def __init__(self, cfg):
        self.cfg = cfg
        self.enabled = cfg["prometheus_enabled"]
        self.data = {"up": 1}
        self._httpd = None
        self._lock = threading.Lock()

    def update(self, **kw):
        with self._lock:
            self.data.update(kw)
        if self.enabled and self.cfg["prometheus_mode"] == "textfile":
            self._write_textfile()

    def _render(self):
        with self._lock:
            snapshot = dict(self.data)
        lines = []
        for k, v in snapshot.items():
            if v is None:
                continue
            if isinstance(v, dict):
                for lk, lv in v.items():
                    lines.append(f'netdeflect_{k}{{proto="{lk}"}} {lv}')
            else:
                lines.append(f"netdeflect_{k} {v}")
        return "\n".join(lines) + "\n"

    def _write_textfile(self):
        try:
            tmp = METRICS_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write(self._render())
            os.replace(tmp, METRICS_FILE)
        except OSError as exc:
            log.debug("metrics textfile write failed: %s", exc)

    def start_http(self):
        if not self.enabled or self.cfg["prometheus_mode"] != "http":
            return
        import http.server
        metrics = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                if self.path != "/metrics":
                    self.send_response(404)
                    self.end_headers()
                    return
                body = metrics._render().encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; version=0.0.4")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        try:
            self._httpd = http.server.ThreadingHTTPServer(
                (self.cfg["prometheus_host"], self.cfg["prometheus_port"]), Handler)
            threading.Thread(target=self._httpd.serve_forever, daemon=True).start()
            log.info("Prometheus metrics on http://%s:%d/metrics",
                     self.cfg["prometheus_host"], self.cfg["prometheus_port"])
        except OSError as exc:
            log.error("Could not start metrics HTTP server: %s", exc)


# --------------------------------------------------------------------------- #
#  Notifications
# --------------------------------------------------------------------------- #

def load_notification_template():
    default = {
        "content": None,
        "embeds": [{
            "title": "DDoS Attack Mitigated: #{{attack_id}}",
            "description": "NetDeflect detected and responded to an attack.",
            "url": "https://github.com/0vm/NetDeflect",
            "color": 16734296,
            "fields": [
                {"name": "Traffic (pre)", "value":
                 "PPS: {{pps}}\nMbit/s: {{mbps}}\nCPU: {{cpu}}", "inline": True},
                {"name": "Mitigation", "value":
                 "Verdict: {{status}}\nDropping: {{dropped_pps}} pps\n"
                 "Passing: {{passed_pps}} pps", "inline": True},
                {"name": "Attack", "value":
                 "Vector: {{attack_vector}}\nCategory: {{attack_category}}\n"
                 "Strategy: {{blocking_strategy}}", "inline": False},
                {"name": "Target", "value":
                 "IP: {{target_ip}}\nPort: {{target_port}}", "inline": True},
                {"name": "Blocked", "value":
                 "IPs: {{block_count}}  Subnets: {{net_count}}", "inline": True},
                {"name": "Report", "value": "{{report_file}}", "inline": False},
            ],
            "footer": {"text": "github.com/0vm/NetDeflect"},
        }],
    }
    if not os.path.exists(TEMPLATE_FILE):
        with open(TEMPLATE_FILE, "w", encoding="utf-8") as fh:
            json.dump(default, fh, ensure_ascii=False, indent=4)
        return default
    try:
        with open(TEMPLATE_FILE, encoding="utf-8") as fh:
            return json.load(fh)
    except json.JSONDecodeError as exc:
        log.error("notification_template.json is invalid JSON (%s); using the "
                  "built-in template and NOT overwriting your file.", exc)
        return default


def _json_escape(value):
    """Escape a value so it is safe to splice into the JSON template as a string
    (attacker-controlled signature names etc. must not break the JSON)."""
    s = json.dumps(str(value))
    return s[1:-1]  # strip the surrounding quotes the template already has


def send_discord(webhook_url, template, fields):
    if not webhook_url or "CHANGE-ME" in webhook_url:
        return False
    import requests
    payload = json.dumps(template)
    for key, value in fields.items():
        payload = payload.replace("{{" + key + "}}", _json_escape(value))
    try:
        r = requests.post(webhook_url, data=payload,
                          headers={"content-type": "application/json"}, timeout=5)
        if r.status_code >= 300:
            log.warning("Discord webhook returned %s", r.status_code)
        return r.status_code < 300
    except Exception as exc:  # noqa: BLE001
        log.warning("Discord webhook failed: %s", exc)
        return False


# ---- rich alerts: Discord embeds and plain-text webhooks -------------------- #

def _verdict_style(verdict, saturated=False):
    """(emoji, embed colour, short label) for a mitigation verdict."""
    v = str(verdict or "").lower()
    if saturated or "saturated" in v:
        return "\U0001F525", 0x8B0000, "Link saturated"
    if v.startswith("mitigated") or "upstream mitigation active" in v:
        return "\u2705", 0x2ECC71, "Mitigated"
    if "partial" in v:
        return "\U0001F7E0", 0xF39C12, "Partially mitigated"
    if v.startswith("no drops") or v == "ongoing":
        return "\U0001F534", 0xE74C3C, "Not yet mitigated"
    if v.startswith("detected"):
        return "\U0001F7E1", 0xF1C40F, "Detected"
    return "\U0001F7E1", 0xF1C40F, (str(verdict) or "Unknown").capitalize()


def _clip(text, limit=1024):
    text = str(text) if text not in (None, "") else "n/a"
    return text if len(text) <= limit else text[:limit - 3] + "..."


def _now_iso():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def build_discord_attack(report, new_vector=False, test=False):
    """A Discord embed for an attack round, coloured by how well it is going."""
    emoji, colour, label = _verdict_style(report["verdict"], report.get("saturated"))
    title = f"{emoji} Attack #{report['attack_num']}: {label}"
    if new_vector:
        title += " (new attack type)"
    if test:
        title = "\U0001F9EA TEST ALERT | " + title
    dropped, pct = report.get("dropped_pps"), report.get("dropped_pct")
    if dropped is None:
        mitigation = "No drop counters on this firewall backend"
    else:
        mitigation = (f"Dropping **{_fmt_int(dropped)}** pps" + (f" ({pct}%)" if pct is not None else "")
                      + f"\nPassing {_fmt_int(report.get('passed_pps'))} pps")
    ports = ", ".join(f"{p} ({pc}%)" for p, pc in report.get("top_ports", [])) or "n/a"
    protos = ", ".join(f"{n} {pc}%" for n, pc in report.get("protocol_mix", [])) or "n/a"
    vectors = [f"\u2022 **{m['name']}** {m['pct']}% \u00b7 {m['category']} \u00b7 "
               f"{'real sources' if m['real_source'] else 'spoofed sources'}"
               for m in report["matched"][:6]]
    if len(report["matched"]) > 6:
        vectors.append(f"\u2022 +{len(report['matched']) - 6} more (see the report)")
    learned = [f"\u2022 `{l['label']}`\n{l['reason']} \u00b7 {l['confidence']} confidence \u00b7 "
               f"{'**dropping**' if l['enforced'] else 'report only'}" for l in report["learned"][:3]]
    real = any(m["real_source"] for m in report["matched"]) or report["blocked_ips"]
    src = [f"{_fmt_int(report.get('unique_sources'))} unique \u00b7 {report.get('source_kind', '')}"]
    if real:
        src += [f"`{s['ip']}` {s['pct']}%" for s in report["top_sources"][:3]]
    fields = [
        {"name": "\U0001F4C8 Incoming", "inline": True,
         "value": f"**{_fmt_int(report['pps'])}** pps\n**{report['mbps']}** Mbit/s\nCPU {report['cpu']}%"},
        {"name": "\U0001F6E1\uFE0F Mitigation", "value": _clip(mitigation), "inline": True},
        {"name": "\U0001F3AF Target", "inline": True,
         "value": _clip(f"`{report['target_ip'] or 'n/a'}`\nPorts: {ports}\n{protos}")},
        {"name": "\U0001F50E Attack vectors", "inline": False,
         "value": _clip("\n".join(vectors) or "Unrecognised (no signature matched)")},
    ]
    if learned:
        fields.append({"name": "\U0001F9E0 Learned pattern", "value": _clip("\n".join(learned)),
                       "inline": False})
    fields += [
        {"name": "\U0001F310 Sources", "value": _clip("\n".join(src)), "inline": True},
        {"name": "\U0001F6AB Blocked", "inline": True,
         "value": f"{_fmt_int(len(report['blocked_ips']))} addresses "
                  f"({_fmt_int(len(report['reflectors_blocked']))} reflectors)\n"
                  f"{_fmt_int(len(report['blocked_nets']))} ranges"},
        {"name": "\u2699\uFE0F Action taken", "value": _clip(report.get("strategy") or "monitoring only"),
         "inline": False},
    ]
    if report.get("action_needed"):
        fields.append({"name": "\u26A0\uFE0F Action needed", "inline": False,
                       "value": _clip("\n".join(f"\u2022 {t}" for t in report["action_needed"]))})
    if report.get("escalated"):
        fields.append({"name": "\U0001F4E1 Upstream", "value": _clip(", ".join(report["escalated"])),
                       "inline": False})
    notes = [n for n in report.get("notes", []) if n]
    if notes:
        fields.append({"name": "\U0001F4DD Notes", "inline": False,
                       "value": _clip("\n".join(f"\u2022 {n}" for n in notes[:6]))})
    rep_line = f"`{report['report_file']}`" if report.get("report_file") else "n/a"
    if _update_tag[0]:
        rep_line += (f"\n[Update available: {_update_tag[0]}]"
                     f"(https://github.com/0vm/NetDeflect/releases/latest)")
    fields.append({"name": "\U0001F4C4 Report", "value": _clip(rep_line), "inline": False})
    return {"title": _clip(title, 256), "description": _clip(report.get("summary", ""), 4000),
            "url": "https://github.com/0vm/NetDeflect", "color": colour, "fields": fields[:25],
            "footer": {"text": f"NetDeflect v{VERSION} \u00b7 {report.get('hostname', '')}"},
            "timestamp": _now_iso()}


def build_discord_end(summary):
    mins, secs = divmod(int(summary["duration"]), 60)
    emoji, _c, label = _verdict_style(summary.get("final_verdict"))
    mbit = round(summary["peak_mbps"] * 8, 1)
    ports = summary.get("top_ports") or []
    fields = [
        {"name": "\u23F1\uFE0F Duration", "value": f"{mins}m {secs}s", "inline": True},
        {"name": "\U0001F4C8 Peak", "value": f"{_fmt_int(summary['peak_pps'])} pps\n{mbit} Mbit/s",
         "inline": True},
        {"name": "\U0001F6E1\uFE0F Peak dropped", "value": f"{_fmt_int(summary.get('peak_dropped_pps'))} pps",
         "inline": True},
        {"name": "\U0001F50E Attack types", "inline": False,
         "value": _clip("\n".join(f"\u2022 {v}" for v in summary.get("vector_list") or [])
                        or "Unrecognised")},
        {"name": "\U0001F3AF Target", "inline": True,
         "value": _clip(f"`{summary.get('target_ip') or 'n/a'}`"
                        + (f"\nPorts: {', '.join(map(str, ports))}" if ports else ""))},
        {"name": "\U0001F6AB Blocked", "value": f"{_fmt_int(summary['total_blocked'])} addresses/ranges",
         "inline": True},
        {"name": "\U0001F501 Rounds", "value": f"{summary.get('rounds', 0)} mitigation round(s)",
         "inline": True},
        {"name": "\U0001F552 Time", "inline": True,
         "value": f"<t:{summary['started']}:T> to <t:{summary['ended']}:T>"},
        {"name": "\U0001F3C1 Final result", "value": f"{emoji} {label}" if summary.get("final_verdict")
                                                    else "n/a", "inline": True},
    ]
    if summary.get("pulse_wave"):
        fields.append({"name": "\u3030\uFE0F Pattern", "inline": False,
                       "value": f"Pulse wave ({summary.get('bursts', 0)} bursts). Protection was "
                                f"held through the quiet gaps."})
    return {"title": f"\u2705 Attack #{summary['attack_id']} ended", "color": 0x2ECC71,
            "description": f"Lasted {mins}m {secs}s and peaked at {_fmt_int(summary['peak_pps'])} pps "
                           f"({mbit} Mbit/s).",
            "fields": fields, "footer": {"text": f"NetDeflect v{VERSION} \u00b7 {socket.gethostname()}"},
            "timestamp": _now_iso()}


def build_text_alert(report, new_vector=False):
    """The same alert as plain multi-line text for Slack, Teams or Mattermost."""
    emoji, _c, label = _verdict_style(report["verdict"], report.get("saturated"))
    lines = [f"{emoji} NetDeflect | Attack #{report['attack_num']} on {report.get('hostname', '')}: "
             f"{label}" + (" (new attack type)" if new_vector else ""),
             report.get("summary", "")]
    vec = "; ".join(f"{m['name']} {m['pct']}% ({'real' if m['real_source'] else 'spoofed'})"
                    for m in report["matched"][:4]) or "unrecognised"
    lines.append(f"Vectors: {vec}")
    for l in report["learned"][:2]:
        lines.append(f"Learned: {l['label']} ({l['reason']}; "
                     f"{'dropping' if l['enforced'] else 'report only'})")
    d = report.get("dropped_pps")
    lines.append(f"Incoming: {_fmt_int(report['pps'])} pps / {report['mbps']} Mbit/s"
                 + (f" | Dropping {_fmt_int(d)} pps ({report.get('dropped_pct')}%) | "
                    f"Passing {_fmt_int(report.get('passed_pps'))} pps" if d is not None else ""))
    ports = ", ".join(f"{p} ({pc}%)" for p, pc in report.get("top_ports", []))
    lines.append(f"Target: {report['target_ip'] or 'n/a'}" + (f" ports {ports}" if ports else ""))
    lines.append(f"Sources: {_fmt_int(report.get('unique_sources'))} unique, "
                 f"{report.get('source_kind', '')} | Blocked: {len(report['blocked_ips'])} addresses, "
                 f"{len(report['blocked_nets'])} ranges")
    lines.append(f"Action taken: {report.get('strategy') or 'monitoring only'}")
    lines += [f"Action needed: {t}" for t in report.get("action_needed", [])]
    if report.get("report_file"):
        lines.append(f"Report: {report['report_file']}")
    return "\n".join(l for l in lines if l)


def build_text_end(summary):
    mins, secs = divmod(int(summary["duration"]), 60)
    return (f"\u2705 NetDeflect | Attack #{summary['attack_id']} ended after {mins}m {secs}s\n"
            f"Peak: {_fmt_int(summary['peak_pps'])} pps / {round(summary['peak_mbps'] * 8, 1)} Mbit/s"
            f" | Peak dropped: {_fmt_int(summary.get('peak_dropped_pps'))} pps"
            f" | Blocked: {_fmt_int(summary['total_blocked'])}\n"
            f"Attack types: {summary['vectors']}"
            + ("\nPattern: pulse wave" if summary.get("pulse_wave") else ""))


def send_discord_embed(webhook_url, embed, mention=""):
    if not webhook_url or "CHANGE-ME" in webhook_url:
        return False
    import requests
    payload = {"embeds": [embed],
               "allowed_mentions": {"parse": ["everyone", "roles", "users"] if mention else []}}
    if mention:
        payload["content"] = mention
    try:
        r = requests.post(webhook_url, json=payload, timeout=5)
        if r.status_code >= 300:
            log.warning("Discord webhook returned %s: %s", r.status_code, r.text[:200])
        return r.status_code < 300
    except Exception as exc:  # noqa: BLE001
        log.warning("Discord webhook failed: %s", exc)
        return False


def send_discord_end(webhook_url, summary):
    """The 'attack ended' summary embed."""
    return send_discord_embed(webhook_url, build_discord_end(summary))


def send_text_webhook(url, text):
    if not url:
        return False
    import requests
    try:
        r = requests.post(url, json={"text": text}, timeout=5)
        return r.status_code < 300
    except Exception as exc:  # noqa: BLE001
        log.warning("Text webhook failed: %s", exc)
        return False


def run_notify_script(cfg, action, report):
    script = cfg["notify_script"]
    if not script:
        return
    argv = [script, action, str(report.get("target_ip", "")),
            str(report.get("attack_vector", report.get("vectors", ""))),
            str(report.get("dropped_pps", "")), str(report.get("attack_id", ""))]
    try:
        inp = json.dumps(report) if cfg["notify_format"] == "json" else None
        subprocess.run(argv, input=inp, text=True, timeout=cfg["notify_script_timeout"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    except Exception as exc:  # noqa: BLE001
        log.warning("notify_script failed: %s", exc)


def write_event_log(cfg, report):
    path = cfg["event_log"]
    if not path:
        return
    if not os.path.isabs(path):
        path = os.path.join(BASE_DIR, path)
    try:
        if os.path.exists(path) and os.path.getsize(path) > 50 * 1024 * 1024:
            os.replace(path, path + ".1")      # keep one 50 MB generation
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(report) + "\n")
    except OSError as exc:
        log.debug("event_log write failed: %s", exc)


# --------------------------------------------------------------------------- #
#  External firewall API
# --------------------------------------------------------------------------- #

def send_ips_to_external_api(cfg, ip_list):
    if not cfg["enable_api_integration"] or not ip_list:
        return True
    import requests
    ip_list = sorted(set(ip_list))
    try:
        headers = json.loads(cfg["additional_headers"] or "{}")
    except json.JSONDecodeError:
        headers = {}
    auth = None
    method = cfg["request_method"].upper()
    am = cfg["auth_method"].lower()
    if am == "basic":
        auth = (cfg["auth_username"], cfg["auth_password"])
    elif am == "bearer":
        headers["Authorization"] = f"Bearer {cfg['auth_token']}"
    elif am == "header" and cfg["auth_token"]:
        headers["Authorization"] = cfg["auth_token"]

    def one_request(batch):
        tmpl = cfg["request_body_template"]
        if tmpl:
            body = (tmpl.replace("{{IP_LIST}}", json.dumps(batch))
                        .replace("{{IP_CSV}}", ",".join(batch))
                        .replace("{{IP}}", batch[0] if batch else "")
                        .replace("{{TIMESTAMP}}", get_timestamp())
                        .replace("{{SOURCE}}", "NetDeflect"))
            try:
                body = json.loads(body)
            except json.JSONDecodeError:
                pass
        else:
            body = {"ips": batch}
        import requests as _rq
        func = getattr(_rq, method.lower(), _rq.post)
        kwargs = {"headers": headers, "timeout": cfg["request_timeout"]}
        if auth:
            kwargs["auth"] = auth
        if method in ("GET", "DELETE"):
            kwargs["params"] = body if isinstance(body, dict) else {}
        elif "json" in headers.get("Content-Type", "").lower() and isinstance(body, (dict, list)):
            kwargs["json"] = body
        else:
            kwargs["data"] = body
        try:
            r = func(cfg["api_endpoint"], **kwargs)
            if not (200 <= r.status_code < 300):
                log.warning("External API returned %s", r.status_code)
            return 200 <= r.status_code < 300
        except Exception as exc:  # noqa: BLE001
            log.warning("External API request failed: %s", exc)
            return False

    mode = cfg["sending_mode"].lower()
    if mode == "single":
        return all(one_request([ip]) for ip in ip_list)
    if mode == "batch":
        size = cfg["max_ips_per_batch"]
        return all(one_request(ip_list[i:i + size]) for i in range(0, len(ip_list), size))
    return one_request(ip_list)


# --------------------------------------------------------------------------- #
#  Timestamps, logging, environment
# --------------------------------------------------------------------------- #

def get_timestamp():
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def get_display_time():
    return datetime.now().strftime("%H:%M:%S")


class TerminalColor:
    """ANSI colours for the live status screen (the classic NetDeflect look)."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GREY = "\033[90m"


def get_output_prefix():
    return (f"{TerminalColor.WHITE}[{TerminalColor.RED}NetDeflect{TerminalColor.WHITE}]"
            f"{TerminalColor.RESET} ")


class _ColourFormatter(logging.Formatter):
    COLOURS = {"WARNING": "\033[93m", "ERROR": "\033[91m",
               "CRITICAL": "\033[91m", "DEBUG": "\033[90m"}
    RESET = "\033[0m"

    def format(self, record):
        msg = super().format(record)
        c = self.COLOURS.get(record.levelname)
        return f"{c}{msg}{self.RESET}" if c else msg


def _use_colour(cfg):
    mode = cfg.get("colour", "auto")
    if mode == "never" or os.environ.get("NO_COLOR"):
        return False
    if mode == "always":
        return True
    return sys.stdout.isatty()


def setup_logging(cfg, args):
    level = getattr(logging, str(args.log_level or cfg.get("log_level", "INFO")).upper(),
                    logging.INFO)
    log.setLevel(level)
    log.handlers.clear()
    plain = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s",
                              datefmt="%Y-%m-%d %H:%M:%S")
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(_ColourFormatter("%(asctime)s [%(levelname)s] %(message)s",
                                          datefmt="%H:%M:%S") if _use_colour(cfg) else plain)
    log.addHandler(console)
    log_file = cfg.get("log_file", "")
    if log_file:
        if not os.path.isabs(log_file):
            log_file = os.path.join(BASE_DIR, log_file)
        try:
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            fh = logging.handlers.RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024,
                                                      backupCount=5)
            fh.setFormatter(plain)
            log.addHandler(fh)
        except OSError as exc:
            log.warning("Could not open log file %s: %s", log_file, exc)


def ensure_dirs():
    for d in (DATA_DIR, CAPTURE_DIR, IP_DIR, ANALYSIS_DIR):
        os.makedirs(d, exist_ok=True)
    try:
        os.chmod(CAPTURE_DIR, 0o700)
    except OSError:
        pass


def ensure_syn_cookies(enabled, dry):
    if not enabled:
        return
    if dry:
        log.info("[dry-run] would enable net.ipv4.tcp_syncookies=1")
        return
    try:
        subprocess.run(["sysctl", "-w", "net.ipv4.tcp_syncookies=1"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
    except Exception:  # noqa: BLE001
        pass


def require_root(cfg):
    if cfg["dry_run"]:
        return
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        log.error("NetDeflect must run as root to capture traffic and manage the "
                  "firewall. Re-run with sudo, or set dry_run = True to test.")
        sys.exit(1)


# --------------------------------------------------------------------------- #
#  Update checker
# --------------------------------------------------------------------------- #

_update_tag = [None]


def check_for_updates(repo="0vm/NetDeflect"):
    try:
        import requests
        r = requests.get(f"https://api.github.com/repos/{repo}/releases/latest", timeout=5)
        if r.status_code != 200:
            return
        tag = r.json().get("tag_name", "")
        if tag and parse_version(tag) > parse_version(VERSION):
            _update_tag[0] = tag
            log.warning("Update available: %s (current v%s) - https://github.com/%s",
                        tag, VERSION, repo)
    except Exception:  # noqa: BLE001
        pass


def start_update_checker(enabled=True, repo="0vm/NetDeflect", hours=12):
    if not enabled:
        return

    def worker():
        time.sleep(5)
        check_for_updates(repo)
        while True:
            time.sleep(max(1, hours) * 3600)
            check_for_updates(repo)
    threading.Thread(target=worker, daemon=True).start()


# --------------------------------------------------------------------------- #
#  Triggers
# --------------------------------------------------------------------------- #

def is_under_attack(pps, mbps, proto_pps, proto_mbps, cfg):
    """Return (triggered, reason). proto_pps/proto_mbps map 'tcp'/'udp'/'icmp'
    to estimated per-protocol rates (may be empty if not sampled)."""
    mode = cfg["trigger_mode"]
    gp, gm = cfg["pps_threshold"], cfg["mbps_threshold"]
    cond_p = (gp <= 0) or (pps > gp)
    cond_m = (gm <= 0) or (mbps > gm)
    if mode == "P" and gp > 0 and pps > gp:
        return True, f"pps {pps} > {gp}"
    if mode == "M" and gm > 0 and mbps > gm:
        return True, f"{mbps:.1f} MB/s > {gm}"
    if mode == "MP" and (gp > 0 or gm > 0) and cond_p and cond_m:
        return True, f"pps {pps}/{gp}, {mbps:.1f}/{gm} MB/s"
    for proto in ("tcp", "udp", "icmp"):
        thr = cfg[f"threshold_{proto}_pps"]
        if thr > 0 and proto_pps.get(proto, 0) > thr:
            return True, f"{proto} {int(proto_pps[proto])} pps > {thr}"
        thrm = cfg[f"threshold_{proto}_mbps"]
        if thrm > 0 and proto_mbps.get(proto, 0) > thrm:
            return True, f"{proto} {proto_mbps[proto]:.1f} MB/s > {thrm}"
    return False, ""


def per_proto_configured(cfg):
    return any(cfg[f"threshold_{p}_{m}"] > 0 for p in ("tcp", "udp", "icmp")
              for m in ("pps", "mbps"))


# --------------------------------------------------------------------------- #
#  Attack lifecycle tracking (with hold-down for pulse-wave attacks)
# --------------------------------------------------------------------------- #

class AttackTracker:
    def __init__(self):
        self.active = False
        self.attack_id = self._seed_id()
        self.start = None
        self.last_over = 0
        self.peak_pps = 0
        self.peak_mbps = 0.0
        self.total_blocked = 0
        self.sigs_seen = set()
        self.crossings = []        # start times of separate bursts (last 10 min)
        self.pulse = False
        self.quiet_seen = False    # traffic fell below the triggers since the last burst
        self.quiet_since = None

    COUNTER_FILE = None  # set lazily (DATA_DIR may be patched in tests)

    @staticmethod
    def _counter_path():
        return os.path.join(DATA_DIR, "attack_counter.json")

    @classmethod
    def _seed_id(cls):
        try:
            with open(cls._counter_path(), encoding="utf-8") as fh:
                return int(json.load(fh).get("last_attack_id", 0))
        except (OSError, ValueError, json.JSONDecodeError):
            return 0

    def _save_id(self):
        try:
            tmp = self._counter_path() + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump({"last_attack_id": self.attack_id}, fh)
            os.replace(tmp, self._counter_path())
        except OSError:
            pass

    def begin(self, pps, mbps):
        self.active = True
        self.attack_id += 1
        self._save_id()
        self.start = time.time()
        self.last_over = time.time()
        self.peak_pps = pps
        self.peak_mbps = mbps
        self.total_blocked = 0
        self.sigs_seen = set()
        self.learned_seen = set()
        self.rounds = 0
        self.peak_dropped = 0
        self.last_verdict = ""
        self.target = ""
        self.ports = Counter()
        self.max_sources = 0
        self.pulse = False
        self.quiet_seen = True     # the first round of an attack is a burst
        self.quiet_since = None
        log.warning("=== Attack #%d started (%d pps, %.1f MB/s) ===",
                    self.attack_id, pps, mbps)

    def note_quiet(self, min_gap=2.0):
        """Traffic is below the triggers. A gap of min_gap seconds or more makes
        the next round a new burst (a pulse), not a continuation."""
        if not self.active:
            return
        now = time.time()
        if self.quiet_since is None:
            self.quiet_since = now
        elif now - self.quiet_since >= min_gap:
            self.quiet_seen = True

    def note_over(self, pps, mbps):
        now = time.time()
        self.last_over = now
        self.peak_pps = max(self.peak_pps, pps)
        self.peak_mbps = max(self.peak_mbps, mbps)
        self.quiet_since = None
        # Count a burst only when traffic actually went quiet in between: a
        # continuous attack runs many mitigation rounds but is one burst.
        if self.quiet_seen:
            self.quiet_seen = False
            self.crossings = [t for t in self.crossings if now - t < 600] + [now]
        if len(self.crossings) >= 3:
            if not self.pulse:
                log.warning("Pulse-wave pattern detected (%d bursts/10min); holding "
                            "mitigation through the gaps", len(self.crossings))
            self.pulse = True

    def update(self, result, sig_names, report=None):
        self.total_blocked += len(result.blocked_ips) + len(result.blocked_nets)
        self.sigs_seen.update(sig_names)
        self.learned_seen.update(d["label"] for d in result.autodetected)
        self.rounds = getattr(self, "rounds", 0) + 1
        if report:
            self.peak_dropped = max(getattr(self, "peak_dropped", 0), report.get("dropped_pps") or 0)
            self.last_verdict = report.get("verdict") or ""
            self.target = report.get("target_ip") or getattr(self, "target", "")
            self.max_sources = max(getattr(self, "max_sources", 0), report.get("unique_sources") or 0)
            for port, pct in report.get("top_ports", []):
                self.ports[port] += pct

    def should_end(self, cfg):
        if not self.active:
            return False
        hold = cfg["holddown_seconds"]
        if self.pulse:
            hold = max(hold, hold * 2)
        return (time.time() - self.last_over) > hold

    def end(self):
        duration = int(time.time() - self.start) if self.start else 0
        learned = sorted(getattr(self, "learned_seen", set()))
        vectors = sorted(self.sigs_seen) + [f"{l} (learned)" for l in learned]
        ports = getattr(self, "ports", Counter())
        summary = {"attack_id": self.attack_id, "duration": duration,
                   "peak_pps": self.peak_pps, "peak_mbps": round(self.peak_mbps, 1),
                   "total_blocked": self.total_blocked,
                   "vectors": ", ".join(vectors) or "unclassified",
                   "vector_list": vectors, "pulse_wave": self.pulse,
                   "started": int(self.start or time.time()), "ended": int(time.time()),
                   "rounds": getattr(self, "rounds", 0),
                   "peak_dropped_pps": getattr(self, "peak_dropped", 0),
                   "final_verdict": getattr(self, "last_verdict", ""),
                   "target_ip": getattr(self, "target", ""),
                   "top_ports": [p for p, _ in ports.most_common(3)],
                   "max_sources": getattr(self, "max_sources", 0),
                   "bursts": len(self.crossings)}
        log.warning("=== Attack #%d ended after %ds (peak %d pps / %.1f MB/s, %d blocked%s) ===",
                    self.attack_id, duration, self.peak_pps, self.peak_mbps,
                    self.total_blocked, ", pulse-wave" if self.pulse else "")
        self.active = False
        return summary


# --------------------------------------------------------------------------- #
#  Reporting
# --------------------------------------------------------------------------- #

def _dash_attack(report):
    """Attack and drop-rate lines for the live status screen."""
    if not report:
        return {}
    vec = (report["matched"][0]["name"] if report["matched"]
           else (report["learned"][0]["label"] if report["learned"] else "unrecognised"))
    out = {"attack": f"#{report['attack_num']} {vec}"}
    if report.get("dropped_pps") is not None:
        out["dropping"] = f"{_fmt_int(report['dropped_pps'])} pps ({report.get('dropped_pct')}%)"
    return out


def sample_report(cfg):
    """A realistic example attack for --test-webhook previews (clearly marked TEST)."""
    r = {"attack_num": 0, "attack_id": "0-test", "timestamp": datetime.now().isoformat(timespec="seconds"),
         "target_ip": "203.0.113.10", "target_port": 53, "pps": 182450, "mbps": 1402.6, "cpu": 4,
         "verdict": "mitigated", "dropped_pps": 179880, "passed_pps": 2570, "saturated": False,
         "attack_vector": "DNS Reflection", "attack_category": "reflection",
         "matched": [{"name": "DNS Reflection", "category": "reflection", "pct": 97.4,
                      "real_source": True}],
         "top_sources": [{"ip": "198.51.100.23", "pct": 2.1}, {"ip": "198.51.100.87", "pct": 1.9},
                         {"ip": "192.0.2.44", "pct": 1.6}],
         "blocked_ips": ["198.51.100.23"] * 412, "blocked_nets": ["198.51.100.0/24"],
         "reflectors_blocked": ["198.51.100.23"] * 412, "spoofed_spared": [],
         "escalated": [], "notes": ["This is a test alert from --test-webhook. No attack is running."],
         "near_misses": [], "hostname": socket.gethostname(), "unique_sources": 431,
         "top_ports": [(53, 98), (443, 1)], "protocol_mix": [("UDP", 99), ("TCP", 1)],
         "dropped_pct": 99, "learned": [], "report_file": "example.attack0.txt",
         "strategy": "1 attack pattern(s) dropped; 412 address(es) blocked, 412 of them "
                     "reflectors; 1 range(s) blocked"}
    r["source_kind"] = _source_kind(r)
    r["summary"] = _summary_sentence(r)
    r["action_needed"] = _action_needed(r, dict(cfg, dry_run=False))
    return r


def _fmt_int(n):
    try:
        return f"{int(n):,}"
    except (TypeError, ValueError):
        return "n/a"


_PROTO_LABEL = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6", 47: "GRE", 50: "ESP"}


def _proto_mix(classification):
    total = sum(classification.proto_counts.values()) or 1
    return [(_PROTO_LABEL.get(p, str(proto_name(p)).upper()), round(100.0 * c / total))
            for p, c in classification.proto_counts.most_common(3)]


def _top_ports(classification):
    total = sum(classification.dport_counts.values()) or 1
    return [(p, round(100.0 * c / total)) for p, c in classification.top_dports[:3]]


def _source_kind(report):
    if any(m["real_source"] for m in report["matched"]) or report["blocked_ips"]:
        return "real (reflectors or bots)"
    n = report.get("unique_sources") or 0
    if n >= 50:
        return "likely spoofed"
    return f"{n} host(s)"


def _summary_sentence(report):
    """One plain-English line: what is hitting the server and what NetDeflect did."""
    if report["matched"]:
        vec = report["matched"][0]["name"]
        if len(report["matched"]) > 1:
            vec += f" (+{len(report['matched']) - 1} more)"
    elif report["learned"]:
        vec = "An unrecognised flood (pattern learned)"
    else:
        vec = "An unrecognised flood"
    where = report["target_ip"] or "this server"
    if report["target_port"] not in ("", None):
        where += f" port {report['target_port']}"
    s = f"{vec} against {where}."
    dropped = report.get("dropped_pps")
    if dropped:
        pct = report.get("dropped_pct")
        s += f" Dropping {_fmt_int(dropped)} pps" + \
             (f" ({pct}% of incoming)" if pct is not None else "") + " in the kernel."
    elif str(report.get("verdict", "")).startswith("upstream"):
        s += " Mitigation has been sent upstream."
    else:
        s += " Nothing is being dropped yet."
    nb, nn = len(report["blocked_ips"]), len(report["blocked_nets"])
    if nb or nn:
        s += f" Blocked {_fmt_int(nb)} address(es)" + (f" and {nn} range(s)" if nn else "") + "."
    elif (report.get("unique_sources") or 0) >= 50 and \
            not any(m["real_source"] for m in report["matched"]):
        s += " The sources look spoofed, so no addresses were blocked."
    return s


def _action_needed(report, cfg):
    """Plain advice for the operator when NetDeflect cannot fully handle it."""
    tips = []
    port = report["target_port"]
    has_port = port not in ("", None)
    if report.get("saturated"):
        tips.append("Your link or network card is full. Filtering on this server cannot fix "
                    "that: ask your host for upstream filtering, or set up [escalation] BGP.")
    enforced = any(l["enforced"] for l in report["learned"])
    acting = [m for m in report["matched"] if m.get("strategy", "filter") != "report"]
    handled = bool(acting) or enforced
    report_only = [m["name"] for m in report["matched"] if m.get("strategy") == "report"]
    if report_only and not handled:
        tips.append(f"Detected {', '.join(report_only[:3])}, but with your current settings it "
                    "can only be reported, not dropped. See Notes for the setting that enables "
                    "dropping it.")
    elif not handled:
        if has_port and port in cfg.get("service_ports", set()):
            tips.append(f"Unrecognised flood with no stable fingerprint. Port {port} is in "
                        "[services], so lockdown limits unknown sources and real players go first.")
        else:
            tips.append("Unrecognised flood with no stable fingerprint, so nothing is being "
                        "dropped. " + (f"If port {port} is your game or VPN port, add it to "
                                       "[services] ports so lockdown protects it. " if has_port else "")
                        + "Otherwise ask your host for upstream filtering.")
        if report["learned"]:
            tips.append("A lower-confidence pattern was learned and is report-only. Review "
                        "new_detected_methods.json, or set block_autodetected_patterns = True.")
    pct = report.get("dropped_pct")
    if handled and report.get("dropped_pps") and pct is not None and pct < 50 \
            and not report.get("saturated"):
        tips.append("Under half of incoming traffic is being dropped. Check the report for a "
                    "second vector or near misses.")
    if cfg.get("dry_run"):
        tips.append("Watch-only mode is on, so nothing is being blocked "
                    "(set [firewall] enable_ban = True).")
    return tips


def build_report(cfg, tracker, pre, eff, classification, result, whitelist):
    import uuid
    target_port = classification.top_dports[0][0] if classification.top_dports else ""
    vectors = classification.signature_names[:]
    for det in result.autodetected:
        vectors.append(f"{det['label']} (auto)")
    report = {
        "attack_id": f"{tracker.attack_id}-{uuid.uuid4().hex[:8]}",
        "attack_num": tracker.attack_id,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "target_ip": whitelist.public_ip or (next(iter(whitelist.own_ips), "")),
        "target_port": target_port,
        "pps": pre["pps"], "mbps": round(pre["mbps"] * 8, 1), "cpu": pre["cpu"],
        "verdict": eff["verdict"], "dropped_pps": eff["dropped_pps"],
        "passed_pps": eff["passed_pps"], "nic_drop_pps": eff.get("nic_drop_pps"),
        "saturated": eff.get("saturated"), "ct_pct": eff.get("ct_pct"),
        "attack_vector": ", ".join(classification.signature_names) or "Unclassified",
        "attack_category": ", ".join(sorted(classification.categories)) or "Unknown",
        "matched": [{"name": s.name, "category": s.category, "pct": round(p, 1),
                     "real_source": s.real_source, "strategy": s.strategy}
                    for s, c, p in classification.matched],
        "top_sources": [{"ip": ip, "pct": round(p, 1)} for ip, c, p in classification.top_sources[:10]],
        "blocked_ips": result.blocked_ips, "blocked_nets": result.blocked_nets,
        "reflectors_blocked": result.reflectors_blocked,
        "spoofed_spared": result.spoofed_spared,
        "autodetected": [d["label"] for d in result.autodetected],
        "escalated": result.escalated, "notes": result.notes,
        "near_misses": [{"name": n, "pct": round(p, 1)} for n, c, p in classification.near_misses],
    }
    dropped, passed = eff.get("dropped_pps"), eff.get("passed_pps")
    report.update({
        "hostname": socket.gethostname(),
        "unique_sources": getattr(classification, "unique_sources", 0),
        "top_ports": _top_ports(classification),
        "protocol_mix": _proto_mix(classification),
        "dropped_pct": (round(100.0 * dropped / max(dropped + (passed or 0), 1))
                        if dropped is not None else None),
        "strategy": getattr(result, "strategy", ""),
        "learned": [{"label": d["label"], "reason": d.get("reason", ""),
                     "confidence": d.get("confidence", ""), "enforced": bool(d.get("enforced")),
                     "coverage_pct": d.get("coverage_pct")} for d in result.autodetected],
    })
    report["source_kind"] = _source_kind(report)
    report["summary"] = _summary_sentence(report)
    report["action_needed"] = _action_needed(report, cfg)
    return report


def write_report_files(cfg, report, classification, eff):
    ts = get_timestamp()
    base = os.path.join(ANALYSIS_DIR, f"{ts}.attack{report['attack_num']}")
    path = base + ".txt"
    lines = [
        f"NetDeflect v{VERSION} analysis report",
        f"Attack ID : {report['attack_id']}",
        f"Time      : {report['timestamp']}",
        f"Target    : {report['target_ip']}  port {report['target_port']}",
        f"Host      : {report.get('hostname', '')}",
        "",
        f"Summary   : {report.get('summary', '')}",
        "",
        "Pre-mitigation:",
        f"  PPS            : {report['pps']}",
        f"  Mbit/s         : {report['mbps']}",
        f"  CPU            : {report['cpu']}%",
        "",
        "Effectiveness (firewall drop counters + saturation signals):",
        f"  Verdict        : {report['verdict']}",
        f"  Dropping       : {report['dropped_pps']} pps",
        f"  Passing (legit): {report['passed_pps']} pps",
        f"  NIC drop pps   : {report['nic_drop_pps']}  (pre-netfilter; >0 = host saturated)",
    ]
    if report.get("ct_pct") is not None:
        lines.append(f"  conntrack use  : {report['ct_pct']:.0f}%")
    lines += ["", f"Classification ({classification.total} packets analysed):"]
    for m in report["matched"]:
        tag = "real source - blockable" if m["real_source"] else "forged source - pattern/rate only"
        lines.append(f"  {m['name']:<34} {m['pct']:5.1f}%  [{m['category']}, {tag}]")
    if not report["matched"]:
        lines.append("  (unclassified)")
    if report["near_misses"]:
        lines.append("")
        lines.append("Near misses (below detection threshold - tune detection_percent):")
        for n in report["near_misses"]:
            lines.append(f"  {n['name']:<34} {n['pct']:5.1f}%")
    lines += ["", "Top sources:"]
    for s in report["top_sources"][:5]:
        lines.append(f"  {s['ip']:<40} {s['pct']:5.1f}%")
    drop_names = ", ".join(m["name"] for m in report["matched"]) or "none"
    lines += ["", "Mitigation:",
              f"  Pattern/rate drops : {drop_names}",
              f"  Forged-source spared: {', '.join(report['spoofed_spared']) or 'none'}",
              f"  IPs blocked    : {len(report['blocked_ips'])} ({len(report['reflectors_blocked'])} reflectors)",
              f"  Subnets blocked: {', '.join(report['blocked_nets']) or 'none'}"]
    if report["autodetected"]:
        lines.append(f"  Auto-detected  : {', '.join(report['autodetected'])}")
    if report["escalated"]:
        lines.append(f"  Upstream RTBH  : {', '.join(report['escalated'])}")
    for note in report["notes"]:
        lines.append(f"  Note           : {note}")
    lines += ["", f"Sources: {report.get('unique_sources', 0)} unique ({report.get('source_kind', '')})",
              "Ports  : " + (", ".join(f"{p} ({pc}%)" for p, pc in report.get("top_ports", [])) or "n/a"),
              "Protos : " + (", ".join(f"{n} {pc}%" for n, pc in report.get("protocol_mix", [])) or "n/a")]
    for l in report.get("learned", []):
        lines.append(f"Learned: {l['label']} ({l['reason']}; {l['confidence']} confidence; "
                     f"{'dropping' if l['enforced'] else 'report only'})")
    if report.get("action_needed"):
        lines += ["", "Action needed:"] + [f"  - {tip}" for tip in report["action_needed"]]
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    except OSError as exc:
        log.warning("Could not write report: %s", exc)
    # JSON sidecar
    try:
        with open(base + ".json", "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
    except OSError:
        pass
    return path


def write_ip_list(cfg, report, classification, result):
    ts = get_timestamp()
    action_of = {}
    for ip in result.blocked_ips:
        action_of[ip] = "reflector" if ip in result.reflectors_blocked else "blocked"
    try:
        with open(os.path.join(IP_DIR, f"{ts}.attack{report['attack_num']}.csv"), "w", encoding="utf-8") as fh:
            fh.write("ip,packets,pct,action\n")
            for ip, c, p in classification.top_sources:
                fh.write(f"{ip},{c},{p:.1f},{action_of.get(ip, 'seen')}\n")
        if result.blocked_ips:
            with open(os.path.join(IP_DIR, f"unique.{ts}.txt"), "w", encoding="utf-8") as fh:
                fh.write("\n".join(result.blocked_ips) + "\n")
    except OSError as exc:
        log.debug("Could not write IP list: %s", exc)


# --------------------------------------------------------------------------- #
#  Learning real clients of your services (peacetime)
# --------------------------------------------------------------------------- #

class KnownClientLearner:
    """Learns which addresses are your real players / VPN users while there is
    no attack, so they keep working first during one.

    Every learn_interval seconds it samples both directions briefly. An address
    counts for that pass only if it sent to one of your service ports AND this
    server replied to it from that port. It must do so in at least two separate
    passes to be learned. Learned clients are remembered for client_memory_hours
    (renewed each time they are seen) and survive restarts. The first payload
    bytes they send are recorded as a baseline, so auto-detection never turns
    your own game protocol into a block."""

    MIN_PASSES = 2
    MAX_CLIENTS = 200000

    def __init__(self, cfg):
        self.cfg = cfg
        self.enabled = cfg["learn_known_clients"]
        self.path = os.path.join(DATA_DIR, "known_clients.json")
        self.clients = {}       # ip -> expiry epoch
        self.passes = {}        # ip -> passes seen (not yet learned)
        self.baseline = defaultdict(set)   # dport -> set of 4-byte prefixes
        self.last = 0
        self._load()

    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as fh:
                data = json.load(fh)
            now = time.time()
            self.clients = {ip: exp for ip, exp in data.get("clients", {}).items() if exp > now}
            for port, prefixes in data.get("baseline", {}).items():
                self.baseline[int(port)] = {bytes.fromhex(p) for p in prefixes}
        except (OSError, ValueError, json.JSONDecodeError):
            pass

    def _save(self):
        try:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump({"clients": self.clients,
                           "baseline": {str(p): sorted(x.hex() for x in v)
                                        for p, v in self.baseline.items()}}, fh)
            os.replace(tmp, self.path)
        except OSError:
            pass

    def known_set(self):
        now = time.time()
        return {ip for ip, exp in self.clients.items() if exp > now}

    def count(self):
        return len(self.known_set())

    def restore_into(self, fw):
        now = time.time()
        live = {ip: int(exp - now) for ip, exp in self.clients.items() if exp - now > 60}
        if live:
            # batched by the hour of remaining lifetime (a handful of calls)
            groups = defaultdict(list)
            for ip, ttl in live.items():
                groups[max(60, (ttl // 3600) * 3600)].append(ip)
            for ttl, ips in groups.items():
                fw.add_known_clients(ips, ttl)
            log.info("Restored %d learned clients", len(live))

    def due(self):
        return self.enabled and time.time() - self.last >= self.cfg["learn_interval"]

    def learn(self, fw, whitelist):
        self.last = time.time()
        ports = self.cfg["service_ports"]
        try:
            packets, _raw, _lt = afpacket_capture(
                self.cfg["network_interface"], 3000, 3, False, 8,
                pcap_bytes=None, include_outgoing=True)
        except OSError as exc:
            log.debug("client learning capture failed: %s", exc)
            return 0
        inbound = defaultdict(set)    # ip -> service ports it sent to
        replied = defaultdict(set)    # ip -> service ports we replied from
        prefixes = defaultdict(Counter)
        for p in packets:
            if p.get("out"):
                if p.get("sport") in ports and p.get("dst"):
                    replied[p["dst"]].add(p["sport"])
            elif p.get("dport") in ports and p.get("src"):
                inbound[p["src"]].add(p["dport"])
                if p.get("payload") and len(p["payload"]) >= 4:
                    prefixes[p["dport"]][(p["src"], p["payload"][:4])] += 1
        seen_now = {ip for ip in inbound if inbound[ip] & replied.get(ip, set())}
        new = []
        ttl = self.cfg["client_memory_hours"] * 3600
        now = time.time()
        for ip in seen_now:
            if ip in self.clients:
                self.clients[ip] = now + ttl       # renew
                new.append(ip)
                continue
            self.passes[ip] = self.passes.get(ip, 0) + 1
            if self.passes[ip] >= self.MIN_PASSES and len(self.clients) < self.MAX_CLIENTS:
                self.clients[ip] = now + ttl
                self.passes.pop(ip, None)
                new.append(ip)
        # forget pass counts for addresses not seen this time, so a one-off
        # spoofed packet weeks apart never adds up to "learned"
        self.passes = {ip: n for ip, n in self.passes.items() if ip in seen_now}
        known = self.known_set()
        for port, ctr in prefixes.items():
            for (src, prefix), _n in ctr.items():
                if src in known and len(self.baseline[port]) < 256:
                    self.baseline[port].add(prefix)
        if new:
            fw.add_known_clients(new, ttl)
        self.clients = {ip: exp for ip, exp in self.clients.items() if exp > now}
        self._save()
        return len(new)


# --------------------------------------------------------------------------- #
#  Live dashboard
# --------------------------------------------------------------------------- #

class Dashboard:
    def __init__(self, cfg):
        mode = cfg.get("live_dashboard", "auto")
        self.tty = sys.stdout.isatty()
        self.on = (mode == "on") or (mode == "auto" and self.tty)
        self.interval = cfg.get("stats_interval", 2)
        self.last_log = 0
        self.last_draw = 0

    @staticmethod
    def _row(label, value, colour=TerminalColor.RED):
        return (f"{get_output_prefix()}{label:>21}: {TerminalColor.WHITE}["
                f"{colour}{value}{TerminalColor.WHITE}]{TerminalColor.RESET}")

    def render(self, state):
        now = time.time()
        if self.on and self.tty:
            if now - self.last_draw < self.interval:
                return
            self.last_draw = now
            C = TerminalColor
            status = state.get("status", "monitoring")
            mitigating = status not in ("monitoring", "watching")
            scolour = C.RED if mitigating else C.GREEN
            rows = [
                f"{get_output_prefix()}{C.BOLD}{VERSION_STRING}{C.RESET}   {C.GREY}{get_display_time()}{C.RESET}",
                self._row("Interface", state.get("iface", "-"), C.CYAN),
                self._row("IP Address", state.get("ip") or "-"),
                self._row("CPU", f"{state.get('cpu', 0)}%"),
                self._row("MB/s", round(state.get("mbps", 0), 2)),
                self._row("Packets Per Second", state.get("pps", 0)),
                self._row("Blocked", state.get("blocked", 0)),
                self._row("Learned Clients", state.get("known", 0)),
                self._row("Status", status, scolour),
            ]
            if mitigating and state.get("attack"):
                rows.append(self._row("Attack", state["attack"], C.YELLOW))
            if mitigating and state.get("dropping"):
                rows.append(self._row("Dropping", state["dropping"], C.GREEN))
            if _update_tag[0]:
                rows.append(self._row("Update", f"{_update_tag[0]} available", C.YELLOW))
            sys.stdout.write("\033[2J\033[H" + "\n".join(rows) + "\n")
            sys.stdout.flush()
        elif now - self.last_log >= max(self.interval, 60):
            self.last_log = now
            log.info("status: %s pps, %.1f Mbit/s, cpu %d%%, %d blocked, %d learned clients",
                     state.get("pps", 0), state.get("mbps", 0.0) * 8, state.get("cpu", 0),
                     state.get("blocked", 0), state.get("known", 0))


# --------------------------------------------------------------------------- #
#  One detection + mitigation round
# --------------------------------------------------------------------------- #

def run_cycle(cfg, ctx, nic_pps, nic_mbps, cpu0, packets=None):
    """Capture (or use the flow samples passed in), classify, re-check triggers
    and, if this really is an attack, mitigate and report. Returns (acted, report)."""
    fw = ctx["fw"]
    whitelist = ctx["whitelist"]
    tracker = ctx["tracker"]
    escalator = ctx["escalator"]
    metrics = ctx["metrics"]
    learner = ctx["learner"]
    signatures = ctx["signatures"]

    ts = get_timestamp()
    flow_mode = packets is not None
    capture_file = None
    if flow_mode:
        if not packets:
            return False, None
    else:
        capture_file = os.path.join(CAPTURE_DIR, f"traffic.{ts}.pcap")
        fw.pre_capture_drop_rate()          # start of the window for XDP drops
        packets = capture_packets(cfg, capture_file)
        if not packets:
            # With XDP, banned sources are dropped in the driver before the
            # sniffer sees them, while the NIC counter still counts them. That is
            # a fully mitigated attack, not a wrong interface.
            xdp_pps = fw.pre_capture_drop_rate()
            if xdp_pps and xdp_pps >= 0.5 * max(nic_pps, 1):
                if tracker.active:
                    tracker.note_over(nic_pps, nic_mbps)
                if time.time() - ctx.get("xdp_note_at", 0) > 60:
                    ctx["xdp_note_at"] = time.time()
                    log.info("About %d pps from banned sources is being dropped in XDP "
                             "before it can be sampled; %s", int(xdp_pps),
                             "holding mitigation" if tracker.active else "nothing new to do")
                metrics.update(attack_active=int(tracker.active), dropped_pps=int(xdp_pps),
                               packets_per_second=nic_pps)
                return True, None
            log.warning("No packets captured this round (is %s the right interface?)",
                        cfg["network_interface"])
            return False, None

    classification = classify(packets, signatures, cfg, ctx["index"], ctx["peer_nets"])
    total = max(classification.total, 1)
    proto_pps, proto_mbps = {}, {}
    for name, nums in (("tcp", (6,)), ("udp", (17,)), ("icmp", (1, 58))):
        share = sum(classification.proto_counts.get(n, 0) for n in nums) / total
        proto_pps[name] = nic_pps * share
        proto_mbps[name] = nic_mbps * share

    trig, reason = is_under_attack(nic_pps, nic_mbps, proto_pps, proto_mbps, cfg)
    if not trig:
        tracker.note_quiet()
        if capture_file and cfg["save_captures"]:
            try:
                os.remove(capture_file)
            except OSError:
                pass
        return False, None

    first_round = not tracker.active
    if first_round:
        tracker.begin(nic_pps, nic_mbps)
        ctx["notified_vectors"] = set()
        ctx["sat_rounds"] = 0
        # Flag the attack for monitoring at once, not only at the end of this
        # round, so a scrape during the first round already sees it.
        metrics.update(attack_active=1, attacks_total=tracker.attack_id)
    tracker.note_over(nic_pps, nic_mbps)
    log.warning("Attack round: %s | detected: %s", reason,
                ", ".join(classification.signature_names) or "unrecognised")

    # Lock service ports down to learned clients while the attack lasts.
    if cfg["lockdown_during_attack"] and cfg["services"] and not fw.lockdown:
        if learner.count() >= cfg["lockdown_min_clients"]:
            fw.set_lockdown(True)
        elif first_round:
            log.info("Service lockdown skipped: only %d clients learned so far "
                     "(lockdown_min_clients = %d)", learner.count(), cfg["lockdown_min_clients"])

    result = plan_and_mitigate(fw, classification, cfg, whitelist)

    # Run pattern learning when no built-in signature actually HARD-DROPS the
    # traffic: either nothing matched, or only weak rate limits did (so a generic
    # SYN flood that is merely rate-limited still gets a real drop rule).
    hard = {sig.strategy for sig, _, _ in classification.matched} & {"filter", "block_src"}
    if not hard:
        for det in autodetect_patterns(packets, classification, whitelist, cfg,
                                       known=learner.known_set(), baseline=learner.baseline):
            is_new = save_autodetected(det)
            log.info("Learned pattern %s [%s] (%s), %.1f%% of traffic (%s)", det["label"],
                     det.get("confidence", "?"), det.get("reason", det["type"]),
                     det["coverage_pct"], "new" if is_new else "seen before")
            result.autodetected.append(det)
            # A high-confidence composite is a confirmed bad actor: enforce it
            # automatically (spoof-safe pattern drop). Lower confidence still waits
            # for block_autodetected_patterns.
            enforce = (det.get("confidence") == "high" and cfg.get("autodetect_enforce", True))
            if not (enforce or cfg["block_autodetected_patterns"]):
                continue
            try:
                sig = Signature(name=det["label"], category=det["category"],
                                proto=det.get("proto", "udp"), dport=det.get("dport"),
                                sport=det.get("sport"), tcp_flags=det.get("tcp_flags"),
                                ttl_min=det.get("ttl"), ttl_max=det.get("ttl"),
                                tos=det.get("tos"), tcp_window=det.get("tcp_window"),
                                payload_hex=det.get("payload_hex"),
                                payload_offset=det.get("payload_offset"),
                                min_len=det.get("min_len"), max_len=det.get("max_len"),
                                action="drop", block_time=det.get("block_time"))
            except ValueError:
                continue
            if det["category"] == "botnet" and det.get("source_ips"):
                targets = [ip for ip in det["source_ips"][:1024] if not whitelist.is_protected(ip)]
                result.blocked_ips += fw.block_many(targets, det.get("block_time"))
                result.filters_applied.append(f"{det['label']} (learned)")
                fw.apply_filter(FilterRule(sig, cfg))
                det["enforced"] = True
                log.warning("Confirmed attacker pattern %s: dropping it and blocking %d "
                            "real source(s)", det["label"], len(targets))
            elif fw.apply_filter(FilterRule(sig, cfg)):
                result.filters_applied.append(f"{det['label']} (learned)")
                det["enforced"] = True
                log.warning("Enforcing learned drop rule %s (%s)", det["label"], det.get("reason"))
        result.dedup()

    if cfg["carpet_pps_threshold"] > 0:
        for prefix, c in classification.dst_prefix_counts.most_common(3):
            pfx_pps = nic_pps * (c / total)
            if pfx_pps > cfg["carpet_pps_threshold"]:
                result.notes.append(f"Carpet bombing across {prefix} (about {int(pfx_pps)} pps)")
                if cfg["carpet_action"] == "rtbh":
                    p = escalator.announce_prefix(prefix)
                    if p:
                        result.escalated.append(p)

    eff = (flow_effectiveness(fw, cfg, nic_pps) if flow_mode
           else measure_effectiveness(fw, cfg["interfaces"], cfg))

    ctx["sat_rounds"] = ctx.get("sat_rounds", 0) + 1 if eff.get("saturated") else 0
    uplink = cfg["uplink_capacity_mbps"]
    over_uplink = uplink > 0 and nic_mbps * 8 >= uplink * 0.9
    saturated_long = cfg["escalate_on_saturation"] and ctx["sat_rounds"] >= cfg["saturation_rounds"]
    if over_uplink or saturated_long:
        tip = whitelist.public_ip
        if tip:
            p = escalator.announce(tip)
            if p and p not in result.escalated:
                result.escalated.append(p)
                result.notes.append("Uplink full: asked upstream to drop traffic for " + p)

    if cfg["enable_api_integration"]:
        # Remember what the API already has only for as long as the block lasts,
        # so an address that comes back after its block expired is sent again.
        now = time.time()
        sent = ctx["api_sent"]
        for ip in [ip for ip, exp in sent.items() if exp <= now]:
            del sent[ip]
        fresh = [ip for ip in result.blocked_ips if ip not in sent]
        if fresh and send_ips_to_external_api(cfg, fresh):
            exp = now + cfg["block_timeout"] if cfg["block_timeout"] else float("inf")
            for ip in fresh:
                sent[ip] = exp

    strategy = []
    if result.filters_applied:
        strategy.append(f"{len(result.filters_applied)} attack pattern(s) dropped")
    if result.blocked_ips:
        strategy.append(f"{len(result.blocked_ips)} address(es) blocked"
                        + (f", {len(result.reflectors_blocked)} of them reflectors"
                           if result.reflectors_blocked else ""))
    if result.blocked_nets:
        strategy.append(f"{len(result.blocked_nets)} range(s) blocked")
    if fw.lockdown:
        strategy.append("service ports locked to learned clients")
    if result.escalated:
        strategy.append("upstream blackhole: " + ", ".join(result.escalated))
    strategy_str = "; ".join(strategy) or "monitoring only"
    result.strategy = strategy_str

    pre = {"pps": nic_pps, "mbps": nic_mbps, "cpu": int(cpu0)}
    report = build_report(cfg, tracker, pre, eff, classification, result, whitelist)
    report_path = write_report_files(cfg, report, classification, eff)
    report["report_file"] = os.path.basename(report_path)
    write_ip_list(cfg, report, classification, result)
    tracker.update(result, classification.signature_names, report)
    ctx["last_report"] = report
    log.warning("Attack #%d: %s", report["attack_num"], report["summary"])
    for tip in report["action_needed"]:
        log.warning("Action needed: %s", tip)

    vectors = set(classification.signature_names) | {d["label"] for d in result.autodetected}
    new_vectors = vectors - ctx.get("notified_vectors", set())
    if first_round or new_vectors or cfg["notify_every_round"]:
        ctx.setdefault("notified_vectors", set()).update(vectors)
        is_new = bool(new_vectors) and not first_round
        if cfg.get("discord_style", "rich") == "template":
            fields = {
                "attack_id": report["attack_num"], "pps": nic_pps,
                "mbps": round(nic_mbps * 8, 1), "cpu": f"{int(cpu0)}%",
                "status": eff["verdict"], "dropped_pps": eff["dropped_pps"],
                "passed_pps": eff["passed_pps"], "block_count": len(result.blocked_ips),
                "net_count": len(result.blocked_nets), "target_ip": report["target_ip"],
                "target_port": report["target_port"], "attack_vector": report["attack_vector"],
                "attack_category": report["attack_category"], "blocking_strategy": strategy_str,
                "summary": report["summary"],
                "action_needed": " ".join(report["action_needed"]) or "none",
                "unique_sources": report["unique_sources"], "source_kind": report["source_kind"],
                "dropped_pct": report["dropped_pct"], "hostname": report["hostname"],
                "top_ports": ", ".join(f"{p} ({pc}%)" for p, pc in report["top_ports"]),
                "protocol_mix": ", ".join(f"{n} {pc}%" for n, pc in report["protocol_mix"]),
                "report_file": report["report_file"] + (
                    f"\n\n[Update available: {_update_tag[0]}](https://github.com/0vm/NetDeflect/releases/latest)"
                    if _update_tag[0] else ""),
            }
            send_discord(cfg["webhook_url"], ctx["template"], fields)
        else:
            send_discord_embed(cfg["webhook_url"], build_discord_attack(report, new_vector=is_new),
                               cfg.get("discord_mention", ""))
        send_text_webhook(cfg["text_webhook_url"], build_text_alert(report, new_vector=is_new))
        run_notify_script(cfg, "attack", report)
    write_event_log(cfg, report)

    metrics.update(attack_active=1, dropped_pps=eff["dropped_pps"] or 0,
                   passed_pps=eff["passed_pps"] or 0, attacks_total=tracker.attack_id,
                   packets_per_second=nic_pps, bytes_per_second=int(nic_mbps * 1048576),
                   lockdown=int(fw.lockdown),
                   blocked_this_round=len(result.blocked_ips) + len(result.blocked_nets),
                   packets_per_second_by_protocol={k: int(v) for k, v in proto_pps.items()})

    deleted = prune_pcaps(cfg["max_pcap_files"])
    deleted += prune_dir(ANALYSIS_DIR, (".txt", ".json"), cfg["max_report_files"])
    deleted += prune_dir(IP_DIR, (".csv", ".txt"), cfg["max_report_files"])
    if deleted:
        log.debug("Removed %d old capture/report files", deleted)
    return True, report


# --------------------------------------------------------------------------- #
#  Blocklist / threat-feed loading
# --------------------------------------------------------------------------- #

def _parse_blocklist_text(text):
    v4, v6 = [], []
    for line in text.splitlines():
        line = line.split(";")[0].split("#")[0].strip()
        if not line:
            continue
        try:
            net = ipaddress.ip_network(line.split()[0], strict=False)
        except ValueError:
            continue
        (v6 if net.version == 6 else v4).append(str(net))
    return v4, v6


def load_blocklist_sources(cfg, whitelist=None):
    v4, v6 = [], []
    path = cfg["blocklist_file"]
    if path:
        if not os.path.isabs(path):
            path = os.path.join(BASE_DIR, path)
        try:
            with open(path, encoding="utf-8") as fh:
                a, b = _parse_blocklist_text(fh.read())
            v4 += a
            v6 += b
        except OSError as exc:
            log.warning("Could not read blocklist_file %s: %s", path, exc)
    for url in cfg["blocklist_urls"]:
        try:
            import requests
            r = requests.get(url, timeout=20)
            if r.status_code == 200:
                a, b = _parse_blocklist_text(r.text)
                v4 += a
                v6 += b
                log.info("Blocklist %s: %d IPv4 and %d IPv6 ranges", url, len(a), len(b))
            else:
                log.warning("Blocklist %s returned HTTP %s; keeping the previous list",
                            url, r.status_code)
        except Exception as exc:  # noqa: BLE001
            log.warning("Could not fetch blocklist %s: %s", url, exc)
    if whitelist is not None:
        # protect_private_ranges promises private, link-local (e.g. the cloud
        # metadata service 169.254.169.254), CGNAT and other non-public space is
        # never blocked; feeds such as FireHOL level1 list those ranges as bogons.
        guard = (_NON_PUBLIC_V4 + _NON_PUBLIC_V6) if getattr(whitelist, "protect_private", False) else []
        skipped = []

        def keep(n):
            net = ipaddress.ip_network(n)
            for w in list(whitelist.networks) + guard:
                if net.version == w.version and net.overlaps(w):
                    skipped.append(n)
                    return False
            return True
        v4 = [n for n in v4 if keep(n)]
        v6 = [n for n in v6 if keep(n)]
        if skipped:
            log.info("Blocklist: skipped %d range(s) covering protected or private addresses "
                     "(e.g. %s)", len(skipped), ", ".join(skipped[:3]))
    return sorted(set(v4)), sorted(set(v6))


def start_blocklist_refresher(cfg, ctx):
    """Re-download blocklist_urls every blocklist_refresh seconds. Reads the
    firewall and whitelist from ctx each time, so a reload that rebuilds the
    firewall is followed."""
    def worker():
        while True:
            time.sleep(max(300, cfg.get("blocklist_refresh", 86400)))
            if not cfg.get("blocklist_urls") or cfg.get("firewall_system") in ("blackhole", "bgp"):
                continue
            try:
                fw = ctx["fw"]
                v4, v6 = load_blocklist_sources(cfg, ctx["whitelist"])
                if v4 or v6:   # never empty the list because a download failed
                    with fw.lock:
                        fw.static_drop4, fw.static_drop6 = v4, v6
                        fw.sync_filters()
            except Exception as exc:  # noqa: BLE001 - keep the refresher alive
                log.warning("Blocklist refresh failed: %s", exc)
    threading.Thread(target=worker, daemon=True, name="blocklist").start()


def build_firewall(cfg, whitelist, signatures):
    """Create the configured backend with everything it needs before setup()."""
    fw = make_firewall(cfg)
    fw.own_ips = set(whitelist.own_ips)
    fw.resolvers = set(resolver_ips()) | {ip for ip in cfg["trusted_ips"] if "/" not in ip}
    fw.signatures = signatures
    fw.static_drop4, fw.static_drop6 = load_blocklist_sources(cfg, whitelist)
    return fw


def apply_static_blocks(fw, cfg):
    """[blocklist] block_ips / block_nets, permanent while NetDeflect runs."""
    perm_ips = [b for b in cfg["block_ips"] if "/" not in b or b.endswith(("/32", "/128"))]
    perm_nets = cfg["block_nets"] + [b for b in cfg["block_ips"] if b not in perm_ips]
    n = 0
    if perm_ips:
        n += len(fw.block_many([b.split("/")[0] for b in perm_ips], timeout=0))
    if perm_nets:
        n += len(fw.block_net_many(perm_nets, timeout=0))
    return n


# Settings that need the firewall torn down and built again on reload.
_REBUILD_KEYS = ("firewall_system", "dry_run")


def pause(seconds, fw):
    """Sleep between mitigation rounds while still expiring blocks (and their
    XDP copies) on time and reacting to stop/reload within a second."""
    end = time.time() + seconds
    while not _stop_flag[0] and not _reload_flag[0]:
        left = end - time.time()
        if left <= 0:
            break
        time.sleep(min(1.0, left))
        try:
            fw.cleanup_expired()
        except Exception:  # noqa: BLE001
            pass


# --------------------------------------------------------------------------- #
#  Tunnel auto-detection
# --------------------------------------------------------------------------- #

_TUNNEL_KINDS = {"gre": 47, "gretap": 47, "ip6gre": 47, "ip6gretap": 47, "erspan": 47,
                 "ipip": 4, "sit": 41}


def detect_tunnels():
    """Returns (endpoints [(ip, proto)], protocol names, wireguard listen ports)."""
    peers, protos, wg_ports = [], set(), set()
    try:
        links = json.loads(run(["ip", "-d", "-j", "link", "show"]).stdout or "[]")
    except Exception:  # noqa: BLE001
        links = []
    for link in links:
        info = link.get("linkinfo") or {}
        kind = info.get("info_kind")
        if kind not in _TUNNEL_KINDS:
            continue
        num = _TUNNEL_KINDS[kind]
        protos.add(proto_name(num))
        remote = (info.get("info_data") or {}).get("remote")
        if remote and remote not in ("any", "0.0.0.0", "::"):
            try:
                ipaddress.ip_address(remote)
                peers.append((remote, num))
            except ValueError:
                pass
    if shutil.which("wg"):
        try:
            for line in run(["wg", "show", "all", "endpoints"]).stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[2] != "(none)":
                    host = parts[2].rsplit(":", 1)[0].strip("[]")
                    try:
                        ipaddress.ip_address(host)
                        peers.append((host, 17))
                    except ValueError:
                        pass
            for line in run(["wg", "show", "all", "listen-port"]).stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[1].isdigit() and int(parts[1]) > 0:
                    wg_ports.add(int(parts[1]))
        except Exception:  # noqa: BLE001
            pass
    return sorted(set(peers)), protos, wg_ports


def apply_tunnel_detection(cfg):
    if not cfg["auto_detect_tunnels"]:
        return
    peers, protos, wg_ports = detect_tunnels()
    if peers:
        cfg["tunnel_peers"] = peers
        log.info("Tunnel endpoints found (their tunnel traffic is trusted): %s",
                 ", ".join(f"{ip}/{proto_name(p)}" for ip, p in peers))
    new_protos = protos - set(cfg["protocols_in_use"])
    if new_protos:
        cfg["protocols_in_use"] = sorted(set(cfg["protocols_in_use"]) | protos)
        log.info("Tunnel protocols in use (never treated as a flood): %s", ", ".join(sorted(new_protos)))
    for port in sorted(wg_ports - cfg["service_ports"] - cfg["bypass_ports"]):
        cfg["services"].append({"name": f"wg{port}", "ports": {port}, "proto": "udp",
                                "preset": "wireguard", "rate_pps": 0, "min_len": 60,
                                "max_len": None, "lockdown": True, "known_rate_pps": 0})
        cfg["service_ports"].add(port)
        log.info("WireGuard on udp/%d protected automatically (invalid packets dropped)", port)
    cfg["learn_known_clients"] = cfg.get("learn_clients_setting", True) and bool(cfg["services"])


# --------------------------------------------------------------------------- #
#  Guided setup
# --------------------------------------------------------------------------- #

def _set_ini(text, section, key, value):
    out, cur, done = [], None, False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            cur = s[1:-1]
        elif cur == section and not done and s.split("=")[0].strip() == key and not s.startswith(";"):
            line = f"{key} = {value}"
            done = True
        out.append(line)
    return "\n".join(out) + "\n"


def run_setup(path):
    print(f"NetDeflect {VERSION} setup. Press Enter to keep the value in [brackets].\n")
    text = CONFIG_TEMPLATE
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            text = fh.read()

    def ask(q, default=""):
        try:
            ans = input(f"{q} [{default}]: ").strip()
        except EOFError:
            ans = ""
        return ans or default

    probe = resolve_interfaces({"interfaces": ["auto"], "network_interface": "auto"})
    iface = ask("Network interface to protect", probe["network_interface"])
    print("\nYour own public ports (game servers, VPN). Examples:")
    print("  7777/udp            a UDP game server")
    print("  25565/tcp           Minecraft Java")
    print("  27015/both          Source engine (game + queries)")
    print("  51820/udp:wireguard WireGuard, drops anything that is not WireGuard")
    print("  1194/udp:openvpn    OpenVPN over UDP")
    ports = ask("Ports, comma separated (empty if none)", "")
    if ports:
        try:
            _parse_services(ports, 0)
        except ValueError as exc:
            print(f"  That does not look right ({exc}); you can fix it later in settings.ini")
    hook = ask("Discord webhook URL for alerts (empty to skip)", "")
    profile = ask("Machine size: vps, server or enterprise", "vps")
    watch = ask("Watch only for now, without blocking? (yes/no)", "no").lower().startswith("y")

    text = _set_ini(text, "capture", "network_interface", iface)
    text = _set_ini(text, "services", "ports", ports)
    if hook:
        text = _set_ini(text, "notification", "webhook_url", hook)
    if profile in PROFILES:
        text = _set_ini(text, "general", "profile", profile)
    text = _set_ini(text, "firewall", "enable_ban", "False" if watch else "True")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(f"\nSaved {path}.")
    print("Next: sudo python3 netdeflect.py --selftest, then start it "
          "(or: sudo systemctl enable --now netdeflect).")


# --------------------------------------------------------------------------- #
#  Signals and CLI
# --------------------------------------------------------------------------- #

_reload_flag = [False]
_stop_flag = [False]


def _handle_hup(signum, frame):
    _reload_flag[0] = True


def _handle_stop(signum, frame):
    _stop_flag[0] = True


def parse_args():
    ap = argparse.ArgumentParser(
        description=f"NetDeflect {VERSION}: DDoS detection and mitigation for Linux servers")
    ap.add_argument("--config", default=SETTINGS_FILE, help="path to settings.ini")
    ap.add_argument("--setup", action="store_true", help="guided setup that writes settings.ini")
    ap.add_argument("--dry-run", action="store_true", help="detect and report, but block nothing")
    ap.add_argument("--once", action="store_true", help="run one check and exit")
    ap.add_argument("--test-webhook", action="store_true", help="send a test alert and exit")
    ap.add_argument("--write-default-config", action="store_true", help="write a fresh settings.ini and exit")
    ap.add_argument("--install-service", action="store_true",
                    help="write and enable the systemd service for this install")
    ap.add_argument("--teardown", action="store_true",
                    help="remove every firewall rule NetDeflect created and exit")
    ap.add_argument("--write-uninstall", nargs="?", const="", metavar="PATH",
                    help="write a standalone uninstall_rules.sh and exit")
    ap.add_argument("--log-level", default=None, help="override the log level")
    ap.add_argument("--block", metavar="IP", help="block an address now")
    ap.add_argument("--block-net", metavar="CIDR", help="block a range now")
    ap.add_argument("--unblock", metavar="IP", help="remove a block")
    ap.add_argument("--for", dest="block_for", type=int, default=None, metavar="SECONDS",
                    help="how long --block/--block-net lasts (0 = until NetDeflect stops)")
    ap.add_argument("--list-blocks", action="store_true", help="list blocked addresses and ranges")
    ap.add_argument("--stats", action="store_true", help="show firewall drop counters")
    ap.add_argument("--selftest", action="store_true", help="check dependencies and settings")
    ap.add_argument("--version", action="version", version=VERSION_STRING)
    return ap.parse_args()


def _run_management(args, cfg):
    if not (args.block or args.block_net or args.unblock or args.list_blocks or args.stats):
        return False
    require_root(cfg)
    fw = make_firewall(cfg)
    fw.own_ips = set(local_interface_ips())
    if args.block or args.block_net or args.unblock:
        fw.ensure_objects()   # never rebuilds a running NetDeflect's rules
    if args.block:
        if "/" in args.block and not args.block.endswith(("/32", "/128")):
            ok = fw.block_net(args.block, timeout=args.block_for)
        else:
            ok = fw.block_src(args.block.split("/")[0], timeout=args.block_for)
        print(f"{'Blocked' if ok else 'Could not block'} {args.block}"
              + (f" for {args.block_for}s" if args.block_for else ""))
    if args.block_net:
        ok = fw.block_net(args.block_net, timeout=args.block_for)
        print(f"{'Blocked' if ok else 'Could not block'} {args.block_net}")
    if args.unblock:
        ok = fw.unblock_src(args.unblock)
        print(f"{'Unblocked' if ok else 'Was not blocked:'} {args.unblock}")
    if args.list_blocks:
        blocks = fw.list_blocks()
        print(f"{len(blocks)} blocked:")
        for b in blocks:
            print(f"  {b}")
    if args.stats:
        dropped = fw.dropped_packets()
        print(f"Firewall: {cfg['firewall_system']}")
        print(f"Packets dropped by NetDeflect: "
              f"{dropped if dropped is not None else 'not available on this firewall'}")
        if isinstance(fw, XdpFirewall):
            if fw.xdp_bin and fw._maps_present():
                out = fw._status()
                print(f"  of which in XDP (NIC driver): {fw._status_drops(out) or 0}")
                print(f"Addresses in the XDP drop map: {len(fw._status_entries(out))}")
            else:
                print("XDP: not loaded (nftables only)")
        print(f"Blocked addresses and ranges: {len(fw.list_blocks())}")
    return True


def _selftest(cfg):
    print(f"NetDeflect {VERSION} self-test (profile: {cfg['profile']})")
    ok = True
    import importlib
    for mod in ("psutil", "requests"):
        try:
            importlib.import_module(mod)
            print(f"  [ok] python module {mod}")
        except ImportError:
            print(f"  [!!] missing python module {mod}  (pip install {mod})")
            ok = False
    needs = {"nft": cfg["firewall_system"] in ("nftables", "xdp"),
             "ipset": cfg["firewall_system"] == "ipset",
             "iptables": cfg["firewall_system"] in ("ipset", "iptables"),
             "ip": True,
             "tcpdump": cfg["capture_method"] in ("tcpdump", "tshark") or bool(cfg["filter_arguments"].strip()),
             "tshark": cfg["capture_method"] == "tshark"}
    for tool, needed in needs.items():
        present = bool(shutil.which(tool))
        if needed and not present:
            print(f"  [!!] missing tool: {tool}")
            ok = False
        elif present:
            print(f"  [ok] {tool}")
    flow_mode = cfg["capture_method"] in ("sflow", "netflow")
    if cfg["capture_method"] == "afpacket" and not hasattr(socket, "AF_PACKET"):
        print("  [!!] packet capture needs Linux")
        ok = False
    if flow_mode:
        try:
            fam = socket.AF_INET6 if ":" in cfg["flow_listen_host"] else socket.AF_INET
            s = socket.socket(fam, socket.SOCK_DGRAM)
            s.bind((cfg["flow_listen_host"], cfg["flow_listen_port"]))
            s.close()
            print(f"  [ok] {cfg['capture_method']} listener can bind "
                  f"{cfg['flow_listen_host']}:{cfg['flow_listen_port']}")
        except OSError as exc:
            print(f"  [!!] cannot bind {cfg['flow_listen_host']}:{cfg['flow_listen_port']}: {exc}")
            ok = False
        if cfg["flow_agents"]:
            print(f"  [ok] accepting flow only from: {', '.join(cfg['flow_agents'])}")
        else:
            print("  [--] accepting flow from any source on that port (set [flow] agents)")
        if cfg["firewall_system"] != "bgp":
            print("  [--] firewall_system is not 'bgp'; flow mode cannot drop locally, "
                  "so set firewall_system = bgp to mitigate upstream")
    else:
        try:
            import psutil
            missing = [i for i in cfg["interfaces"] if i not in psutil.net_if_stats()]
            if missing:
                print(f"  [!!] interface not found: {', '.join(missing)}")
                ok = False
            else:
                print(f"  [ok] interface(s): {', '.join(cfg['interfaces'])}")
        except ImportError:
            pass
    if cfg["firewall_system"] == "xdp":
        if shutil.which("xdp-filter"):
            print(f"  [ok] xdp-filter present: banned sources drop in the NIC driver "
                  f"(XDP, {cfg['xdp_mode']} mode)")
        else:
            print("  [--] firewall_system=xdp but xdp-filter is not installed (package "
                  "xdp-tools); it will run as nftables only until you install it")
    if cfg["firewall_system"] == "bgp":
        if cfg["bgp_enabled"] or cfg["enable_api_integration"]:
            paths = []
            if cfg["bgp_enabled"]:
                paths.append(f"BGP via {cfg['bgp_mode']}")
            if cfg["enable_api_integration"]:
                paths.append("external API")
            print(f"  [ok] out-of-band mitigation: {', '.join(paths)}")
        else:
            print("  [--] bgp backend but no upstream set (enable [escalation] bgp_enabled "
                  "or [external_firewall] enable_api_integration)")
    sigs = load_signatures(cfg)
    print(f"  [{'ok' if sigs else '!!'}] {len(sigs)} attack signatures loaded")
    if cfg["services"]:
        for svc in cfg["services"]:
            ports = sorted(svc["ports"])
            pr = f"{ports[0]}-{ports[-1]}" if len(ports) > 1 else str(ports[0])
            print(f"  [ok] protecting {pr}/{svc['proto']} ({svc['preset']})")
    else:
        print("  [--] no [services] ports set; game/VPN ports get no extra protection")
    if "CHANGE-ME" in cfg["webhook_url"] and not cfg["text_webhook_url"] and not cfg["notify_script"]:
        print("  [--] no alerts configured (set [notification] webhook_url)")
    if cfg["dry_run"]:
        print("  [--] watch-only mode: nothing will be blocked")
    print("Self-test:", "PASS" if ok else "FAIL")
    return ok


def main():
    args = parse_args()
    global SETTINGS_FILE  # noqa: PLW0603
    SETTINGS_FILE = args.config

    if args.write_default_config:
        write_default_config(args.config)
        print(f"Wrote default settings to {args.config}")
        return
    if args.write_uninstall is not None:
        path = write_uninstall_script(args.write_uninstall or None)
        print(f"Wrote {path}")
        return
    if args.teardown:
        # Config-free: must work even when settings.ini is missing or broken, so
        # a stop or a manual cleanup always clears the rules.
        setup_logging({"log_file": "", "log_level": args.log_level or "INFO",
                       "colour": "auto"}, args)
        removed = teardown_all()
        print("Removed:", ", ".join(removed) if removed else "nothing (no NetDeflect rules present)")
        return
    if args.setup:
        run_setup(args.config)
        return
    if args.install_service:
        require_root({"dry_run": False})
        install_service(args.config)
        return

    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
    if args.dry_run:
        cfg["dry_run"] = True

    setup_logging(cfg, args)
    ensure_dirs()
    flow_mode = cfg["capture_method"] in ("sflow", "netflow")
    if not flow_mode:
        resolve_interfaces(cfg)
        apply_tunnel_detection(cfg)
    else:
        # Flow telemetry is read from the network, not a local NIC, and there is
        # no local traffic to learn clients from.
        cfg["learn_known_clients"] = False

    if args.selftest:
        sys.exit(0 if _selftest(cfg) else 1)
    if _run_management(args, cfg):
        return

    source = (f"{cfg['capture_method']} on {cfg['flow_listen_host']}:{cfg['flow_listen_port']}"
              if flow_mode else f"interface {','.join(cfg['interfaces'])}")
    log.info("%s starting (profile %s, firewall %s, %s%s)", VERSION_STRING,
             cfg["profile"], cfg["firewall_system"], source,
             ", WATCH ONLY" if cfg["dry_run"] else "")

    template = load_notification_template()
    if args.test_webhook:
        sample = sample_report(cfg)
        if cfg["discord_style"] == "template":
            ok = send_discord(cfg["webhook_url"], template, {
                "attack_id": 0, "pps": sample["pps"], "mbps": sample["mbps"], "cpu": "4%",
                "status": "test", "dropped_pps": sample["dropped_pps"],
                "passed_pps": sample["passed_pps"], "block_count": 0, "net_count": 0,
                "target_ip": sample["target_ip"], "target_port": sample["target_port"],
                "attack_vector": "Test alert", "attack_category": "test",
                "blocking_strategy": sample["strategy"], "summary": sample["summary"],
                "action_needed": "none", "unique_sources": sample["unique_sources"],
                "source_kind": sample["source_kind"], "dropped_pct": sample["dropped_pct"],
                "hostname": sample["hostname"], "top_ports": "53 (98%)",
                "protocol_mix": "UDP 99%", "report_file": "n/a"})
        else:
            ok = send_discord_embed(cfg["webhook_url"], build_discord_attack(sample, test=True))
        ok2 = send_text_webhook(cfg["text_webhook_url"], build_text_alert(sample))
        print("Discord:", "sent" if ok else "not sent (check webhook_url)")
        if cfg["text_webhook_url"]:
            print("Text webhook:", "sent" if ok2 else "failed")
        return

    require_root(cfg)

    signatures = load_signatures(cfg)
    if not signatures:
        log.error("No attack signatures loaded (is methods.json next to netdeflect.py?)")
        sys.exit(1)
    whitelist = WhitelistGuard(cfg)

    fw = build_firewall(cfg, whitelist, signatures)
    if not fw.setup():
        log.error("Could not load firewall rules; see the error above")
        if not cfg["dry_run"]:
            sys.exit(1)
    static = apply_static_blocks(fw, cfg)
    if static:
        log.info("Applied %d permanent block(s) from settings", static)

    learner = KnownClientLearner(cfg)
    learner.restore_into(fw)

    ensure_syn_cookies(cfg["enable_syn_cookies"], cfg["dry_run"])
    start_update_checker(cfg["check_for_updates"], "0vm/NetDeflect")

    # The bgp backend owns an Escalator (its mitigation path); share that one so a
    # single BGP state is kept. Otherwise create our own for uplink/carpet RTBH.
    escalator = fw.escalator if isinstance(fw, BgpFirewall) else Escalator(cfg)
    metrics = Metrics(cfg)
    metrics.start_http()
    tracker = AttackTracker()
    dashboard = Dashboard(cfg)

    collector = None
    if flow_mode:
        collector = FlowCollector(cfg)
        try:
            collector.open()
        except OSError as exc:
            log.error("Could not start the flow collector on %s:%d: %s",
                      cfg["flow_listen_host"], cfg["flow_listen_port"], exc)
            fw.teardown()
            sys.exit(1)

    ctx = {"fw": fw, "whitelist": whitelist, "tracker": tracker, "escalator": escalator,
           "metrics": metrics, "learner": learner, "signatures": signatures,
           "index": SignatureIndex(signatures), "peer_nets": _peer_networks(cfg),
           "template": template, "api_sent": {}, "notified_vectors": set(),
           "sat_rounds": 0, "collector": collector}
    start_blocklist_refresher(cfg, ctx)

    try:
        signal.signal(signal.SIGHUP, _handle_hup)
    except (AttributeError, ValueError):
        pass
    signal.signal(signal.SIGINT, _handle_stop)
    signal.signal(signal.SIGTERM, _handle_stop)

    log.info("Watching for attacks (%s: %d pps / %g MB/s)%s", cfg["trigger_mode"],
             cfg["pps_threshold"], cfg["mbps_threshold"],
             "; per-protocol triggers on" if per_proto_configured(cfg) else "")

    blocked_count, blocked_at = 0, 0
    last_proto_check = 0
    last_health = time.time()
    try:
        while not _stop_flag[0]:
            if _reload_flag[0]:
                _reload_flag[0] = False
                log.info("Reloading settings and signatures")
                reloaded, rebuild = False, False
                try:
                    newcfg = load_config(SETTINGS_FILE)
                    if args.dry_run:
                        newcfg["dry_run"] = True      # --dry-run outlives a reload
                    if flow_mode:
                        newcfg["learn_known_clients"] = False
                    else:
                        resolve_interfaces(newcfg)
                        apply_tunnel_detection(newcfg)
                    if flow_mode != (newcfg["capture_method"] in ("sflow", "netflow")):
                        log.warning("capture_method changed between packet capture and "
                                    "sflow/netflow; restart NetDeflect to switch")
                        newcfg["capture_method"] = cfg["capture_method"]
                    rebuild = any(newcfg.get(k) != cfg.get(k) for k in _REBUILD_KEYS)
                    if newcfg["firewall_system"] in ("ipset", "iptables") and \
                            newcfg["interfaces"] != cfg["interfaces"]:
                        rebuild = True        # iptables hooks are per interface
                    with fw.lock:
                        cfg.clear()
                        cfg.update(newcfg)
                    reloaded = True
                except ConfigError as exc:
                    log.error("Reload failed, keeping the previous settings:\n%s", exc)
                sigs = load_signatures(cfg)
                if sigs:
                    signatures = sigs
                    ctx["signatures"] = sigs
                    ctx["index"] = SignatureIndex(sigs)
                ctx["peer_nets"] = _peer_networks(cfg)
                if reloaded:
                    # trusted_ips / networks / peers may have changed
                    whitelist = WhitelistGuard(cfg)
                    ctx["whitelist"] = whitelist
                    escalator.enabled = cfg["bgp_enabled"]
                if rebuild:
                    log.warning("Firewall settings changed (%s, %s); rebuilding NetDeflect's rules",
                                cfg["firewall_system"], "watch only" if cfg["dry_run"] else "blocking")
                    was_bgp = isinstance(fw, BgpFirewall)
                    try:
                        fw.teardown()
                    except Exception as exc:  # noqa: BLE001
                        log.warning("Removing the previous rules failed: %s", exc)
                    fw = build_firewall(cfg, whitelist, signatures)
                    if not fw.setup():
                        log.error("Could not load firewall rules after reload; see the error above")
                    apply_static_blocks(fw, cfg)
                    learner.restore_into(fw)
                    ctx["fw"] = fw
                    if isinstance(fw, BgpFirewall):
                        escalator = fw.escalator
                    elif was_bgp:
                        escalator = Escalator(cfg)
                    ctx["escalator"] = escalator
                elif reloaded:
                    fw.apply_config(cfg)
                    fw.signatures = signatures
                    fw.own_ips = set(whitelist.own_ips)
                    fw.resolvers = set(resolver_ips()) | {ip for ip in cfg["trusted_ips"] if "/" not in ip}
                    fw.static_drop4, fw.static_drop6 = load_blocklist_sources(cfg, whitelist)
                    fw.sync_filters()
                    apply_static_blocks(fw, cfg)
                else:
                    fw.signatures = signatures
                    fw.sync_filters()

            flow_packets = None
            if flow_mode:
                import psutil
                try:
                    flow_packets, pps, mbps, ndg = collector.collect(cfg["capture_seconds"])
                except OSError as exc:
                    log.error("Flow collector error: %s", exc)
                    time.sleep(2)
                    continue
                cpu, ok, busiest = psutil.cpu_percent(), True, f"flow/{cfg['capture_method']}"
            else:
                try:
                    pps, mbps, cpu, ok, busiest = get_network_stats_multi(cfg["interfaces"])
                except Exception as exc:  # noqa: BLE001
                    log.error("Could not read network counters: %s", exc)
                    time.sleep(2)
                    continue
                if not ok:
                    log.error("Interface %s not found; set [capture] network_interface",
                              ",".join(cfg["interfaces"]))
                    time.sleep(10)
                    continue
                cfg["network_interface"] = busiest

            global_trig = is_under_attack(pps, mbps, {}, {}, cfg)[0]
            if tracker.active and not global_trig and not per_proto_configured(cfg):
                tracker.note_quiet()
            want_proto = (per_proto_configured(cfg) and
                          time.time() - last_proto_check >= cfg["per_protocol_check_interval"])
            acted = False
            if global_trig or want_proto:
                last_proto_check = time.time()
                try:
                    acted, _ = run_cycle(cfg, ctx, pps, mbps, cpu, packets=flow_packets)
                except Exception as exc:  # noqa: BLE001
                    log.exception("Error during mitigation: %s", exc)
                if acted:
                    pause(cfg["mitigation_pause"], fw)

            if not acted:
                if not tracker.active and learner.due():
                    try:
                        n = learner.learn(fw, whitelist)
                        if n:
                            log.debug("Learned or renewed %d clients", n)
                    except Exception as exc:  # noqa: BLE001
                        log.debug("Client learning failed: %s", exc)
                if time.time() - blocked_at > 30 and not cfg["dry_run"]:
                    blocked_count, blocked_at = fw.count_blocks(), time.time()
                dashboard.render({"iface": busiest, "ip": whitelist.public_ip, "cpu": int(cpu),
                                  "pps": pps, "mbps": mbps, "blocked": blocked_count,
                                  "known": learner.count(),
                                  "status": "mitigating" if tracker.active else "watching",
                                  **_dash_attack(ctx.get("last_report") if tracker.active else None)})
                if tracker.active and tracker.should_end(cfg):
                    summary = tracker.end()
                    if fw.lockdown:
                        fw.set_lockdown(False)
                    escalator.withdraw_all()
                    metrics.update(attack_active=0, lockdown=0)
                    if summary and cfg["notify_on_end"]:
                        send_text_webhook(cfg["text_webhook_url"], build_text_end(summary))
                        send_discord_end(cfg["webhook_url"], summary)
                        run_notify_script(cfg, "ended", summary)
                metrics.update(packets_per_second=pps, bytes_per_second=int(mbps * 1048576),
                               cpu_percent=int(cpu),
                               blocked=blocked_count, known_clients=learner.count())

            if time.time() - last_health > 30:
                last_health = time.time()
                if not fw.healthy():
                    log.warning("NetDeflect's firewall rules were removed by another program "
                                "(firewall restart or Docker?); putting them back")
                    fw.setup()
                    apply_static_blocks(fw, cfg)
                    learner.restore_into(fw)
            fw.cleanup_expired()
            escalator.cleanup()
            if args.once:
                break
    finally:
        try:
            escalator.withdraw_all()
        except Exception:  # noqa: BLE001
            pass
        if collector:
            collector.close()
        try:
            fw.teardown()      # each backend leaves nothing behind unless it is watch-only
        except Exception:  # noqa: BLE001
            pass
    log.info("NetDeflect stopped")


if __name__ == "__main__":
    main()
