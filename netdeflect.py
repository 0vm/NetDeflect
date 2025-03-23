# Terminal color definitions
class TerminalColor:
    BLACK   = '\033[30m'
    RED     = '\033[91m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    BLUE    = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN    = '\033[96m'
    WHITE   = '\033[97m'
    DARK_GRAY     = '\033[90m'
    LIGHT_RED     = '\033[91m'
    LIGHT_GREEN   = '\033[92m'
    LIGHT_YELLOW  = '\033[93m'
    LIGHT_BLUE    = '\033[94m'
    LIGHT_MAGENTA = '\033[95m'
    LIGHT_CYAN    = '\033[96m'
    LIGHT_WHITE   = '\033[97m'
    PURPLE = '\033[35m'
    RESET  = '\033[0m'

# Version information class
class ApplicationVersion:
  version = "NetDeflect v1.0"

try:
  import os
  import sys
  import subprocess
  from subprocess import DEVNULL, STDOUT
  import json
  import configparser
  import re
  from datetime import datetime
  import requests
  import psutil
  import time
  import socket
  import threading
except ImportError:
  # Format current timestamp
  def get_timestamp():
    now = datetime.now()
    timestamp = now.strftime("%d-%m-%y-%H:%M:%S")
    return timestamp

  # Exit application
  exit()

# Set recursion limit to handle large data processing
sys.setrecursionlimit(100000000)

# Format current timestamp
def get_timestamp():
  now = datetime.now()
  timestamp = now.strftime("%d-%m-%y-%H:%M:%S")
  return timestamp

# Format current timestamp
def get_timeonly():
  now = datetime.now()
  timestamp = now.strftime("%H:%M:%S")
  return timestamp

# Generate console output prefix
def get_output_prefix():
  return f"{TerminalColor.LIGHT_WHITE}[{TerminalColor.RED}{ApplicationVersion.version}{TerminalColor.LIGHT_WHITE}][{TerminalColor.PURPLE}{get_timeonly()}{TerminalColor.LIGHT_WHITE}]{TerminalColor.RESET}"

# Global variables
blocked_ips = []
attack_status = "None"

try:
  # Load configuration file
  config = configparser.ConfigParser()
  config.read('settings.ini', encoding='utf-8')

  # Parse configuration settings
  ip_method = config["ip_detection"]["ip_method"]
  firewall_system     = config["firewall"]["firewall_system"]
  webhook_url         = config["notification"]["webhook_url"]
  detection_threshold = int(config["triggers"]["detection_threshold"])
  pps_threshold       = int(config["triggers"]["pps_threshold"])
  trigger_mode        = config["triggers"]["trigger_mode"]
  mitigation_pause    = int(config["triggers"]["mitigation_pause"])
  mbps_threshold      = int(config["triggers"]["mbps_threshold"])
  packet_count        = int(config["triggers"]["packet_count"])
  network_interface   = config["capture"]["network_interface"]
  filter_arguments    = config["capture"]["filter_arguments"]
  trusted_ips         = config["whitelist"]["trusted_ips"].split(", ")
  enable_fallback_blocking = config.getboolean("advanced_mitigation", "enable_fallback_blocking")


except Exception as e:
  print(str(e))
  # Default configuration template
  config_template = """
; Please read all comments carefully before modifying values.
; This file controls application behavior, including detection thresholds, notifications, and firewall mitigation.
; Do not remove section headers (e.g., [capture], [triggers]) or field names.

# Your servers displayed IP address method.
[ip_detection]
# Options: google_dns, opendns, ipify, icanhazip, local
ip_method = google_dns

########################################
# NETWORK PACKET CAPTURE CONFIGURATION
########################################

[capture]
# The name of your network interface.
# Use `ip a` or `ifconfig` to identify your active interface (e.g., eth0, wlan0, enp3s0).
network_interface=eth0

# Additional filter arguments for tcpdump (advanced).
# Leave empty for full traffic capture.
# Example for SYN/ACK packets only: tcp[tcpflags] & (tcp-syn|tcp-ack) != 0
filter_arguments=

########################################
# NOTIFICATION SETTINGS
########################################

[notification]
# Discord Webhook URL used to send alerts during an attack.
# You can generate one by editing a Discord channel → Integrations → Webhooks.
webhook_url=https://discord.com/api/webhooks/CHANGE-ME

########################################
# ATTACK DETECTION & MITIGATION SETTINGS
########################################

[triggers]
# What condition should trigger mitigation?
# Options:
#   P  - Packets Per Second threshold
#   M  - Megabytes Per Second threshold
#   MP - Both PPS and MBPS must be exceeded (recommended)
#   MEGABYTES IS NOT THE SAME AS MEGABITS, 1 BYTE = 8 BITS!
trigger_mode=MP

# The minimum number of packets per second to consider an attack.
# Lower this value to make detection more sensitive.
pps_threshold=10000

# The minimum network speed in megabytes per second to consider an attack.
# Set to 0 to disable MBPS threshold.
# 240 Mbit / 8 = 30 MByte/s
mbps_threshold=30

# Number of seconds to pause between automatic mitigations.
# Helps reduce repeated action during ongoing attacks.
mitigation_pause=15

# Number of packets to capture during an attack for analysis.
# Lower this if you experience memory or performance issues.
packet_count=2000

# Number of attack-type occurrences required to confirm an attack.
# Acts as a sensitivity filter — higher value = stricter classification.
detection_threshold=500

########################################
# FIREWALL / BLOCKING SYSTEM CONFIGURATION
########################################

[firewall]
# Select the blocking method for malicious IPs.
# Options:
#   iptables   - Traditional firewall (Linux)
#   ufw        - Ubuntu Firewall wrapper
#   ipset      - Efficient IP list blocking
#   blackhole  - Adds a null route to silently drop traffic (recommended)
firewall_system=blackhole

########################################
# ADVANCED MITIGATION SETTINGS
########################################

[advanced_mitigation]
# Enable fallback blocking when no specific attack signatures are detected
# Set to False to only block when a specific attack signature is identified
enable_fallback_blocking=False

########################################
# IP WHITELISTING
########################################

[whitelist]
# List of IPs that should NEVER be blocked, such as your home IP or critical infrastructure.
# As it is in beta, please ensure to add your IP address to avoid being blocked.
# Use a comma and space between entries. Example: 1.1.1.1, 8.8.8.8, 139.99.201.1
trusted_ips=8.8.8.8, 8.8.4.4, 1.1.0.1, 1.1.1.1
"""
  # Write default configuration
  with open("settings.ini", "w", encoding='utf-8') as outfile:
      outfile.write(config_template)

  # Inform user
  print(f"{get_output_prefix()} Please configure settings.ini then restart the program")

  # Exit application
  exit()

def get_ip(method):
    if method == "google_dns":
        return subprocess.getoutput('dig TXT +short o-o.myaddr.l.google.com @ns1.google.com').replace('"', '').strip()
    elif method == "opendns":
        return subprocess.getoutput('dig +short myip.opendns.com @resolver1.opendns.com').strip()
    elif method == "ipify":
        return requests.get("https://api.ipify.org", timeout=5).text.strip()
    elif method == "icanhazip":
        return requests.get("https://icanhazip.com", timeout=5).text.strip()
    elif method == "local":
        return socket.gethostbyname(socket.gethostname())
    else:
        raise ValueError(f"Unknown IP detection method: {method}")
    
system_ip = get_ip(ip_method)

# Create required directory structure
def dir():
    # Define application directories
    directories = [
        "./application_data",
        "./application_data/captures",
        "./application_data/ips",
        "./application_data/attack_analysis"
    ]
    
    # Create each directory if it doesn't exist
    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
        except Exception:
            pass

# Configure ipset tables for IP filtering
def configure_ipset():
    # Create IP filtering tables
    subprocess.call('ipset -N blocked_ips hash:net family inet', shell=True, stdout=DEVNULL, stderr=STDOUT)
    subprocess.call('ipset -N trusted_ips hash:net family inet', shell=True, stdout=DEVNULL, stderr=STDOUT)

    # Configure iptables rules
    subprocess.call('iptables -t raw -I PREROUTING -m set --match-set blocked_ips src -j DROP', shell=True, stdout=DEVNULL, stderr=STDOUT)
    subprocess.call('iptables -t raw -I PREROUTING -m set --match-set trusted_ips src -j ACCEPT', shell=True, stdout=DEVNULL, stderr=STDOUT)

def is_protected_ip(ip_address):
  # Check if IP is already in blocked list
  if ip_address in blocked_ips:
    return True

  # Protect system's own IP
  if ip_address == system_ip:
    return True

  # Check against trusted IPs list
  if ip_address in trusted_ips:
    return True

  # IP is not protected
  return False

# Format IP address display
def format_ip_display(ip_address):
  length = len(ip_address)
  if 6 <= length <= 15:
      spaces = " " * (15 - length)
      return f"{ip_address}{spaces}"
  return ip_address

def block_ip(ip_address):
  try:
    # Clean up IP string
    ip_address = ip_address.strip()

    # Format for display
    formatted_ip = format_ip_display(ip_address)

    # Skip protected IPs
    if is_protected_ip(ip_address):
      return False

    # Select appropriate firewall command
    cmd = ""
    if firewall_system == 'ufw':
        cmd = f"sudo ufw deny from {ip_address}"
    elif firewall_system == 'ipset':
        cmd = f"ipset -A blocked_ips {ip_address}"
    elif firewall_system == "iptables":
        cmd = f"iptables -A INPUT -s {ip_address} -j DROP"
    elif firewall_system == "blackhole":
        cmd = f"ip route add blackhole {ip_address}"
    else:
        print(f"{get_output_prefix()} Unrecognized firewall_system! Please select \"ufw\", \"iptables\", \"ipset\", or \"blackhole\"")
        exit()
    
    # Execute firewall command
    if cmd:
        subprocess.call(cmd, shell=True, stdout=DEVNULL, stderr=STDOUT)
        print(f"{get_output_prefix()} Blocked malicious IP: {TerminalColor.BLUE}[{TerminalColor.RED}{formatted_ip}{TerminalColor.BLUE}]{TerminalColor.RESET}")
        blocked_ips.append(ip_address)
        return True

  except Exception as e:
    print(f"{get_output_prefix()} Error occurred: {TerminalColor.BLUE}[{TerminalColor.RED}{e}{TerminalColor.BLUE}]{TerminalColor.RESET}")
  
  return False

update_available = False
latest_version_tag = ""

def check_for_updates():
    global update_available, latest_version_tag
    try:
        # GitHub API URL for latest release
        api_url = "https://api.github.com/repos/0vm/NetDeflect/releases/latest"
        
        # Get current version number (extract from version string)
        current_version = ApplicationVersion.version.split("v")[1].strip() if "v" in ApplicationVersion.version else "1.0"
        
        # Request latest release info
        response = requests.get(api_url, timeout=5)
        if response.status_code != 200:
            return
        
        # Parse response
        release_data = json.loads(response.text)
        latest_version_tag = release_data.get('tag_name', '')
        
        # Extract version number from tag (removing 'v' if present)
        latest_version = latest_version_tag.replace('v', '').strip()
        
        # Simple version comparison (this may not work for complex version schemes)
        if latest_version > current_version:
            # Mark update as available
            update_available = True
    except Exception as e:
        # Silently fail - don't disrupt main application
        pass


def start_update_checker():
    def update_check_worker():
        # Initial delay to let application start properly
        time.sleep(5)
        
        # Do initial check
        check_for_updates()
        
        # Check periodically (every 12 hours)
        while True:
            time.sleep(43200)  # 12 hours
            check_for_updates()
    
    # Start update checker in background thread
    update_thread = threading.Thread(target=update_check_worker)
    update_thread.daemon = True  # Thread will exit when main program exits
    update_thread.start()

def display_update_notification():
    global update_available, latest_version_tag
    if update_available:
        print("\n" + "=" * 80)
        print(f"{get_output_prefix()} {TerminalColor.GREEN}Update Available!{TerminalColor.RESET}")
        print(f"{get_output_prefix()} Current Version: {TerminalColor.BLUE}[{TerminalColor.RED}{ApplicationVersion.version}{TerminalColor.BLUE}]{TerminalColor.RESET}")
        print(f"{get_output_prefix()} Latest Version:  {TerminalColor.BLUE}[{TerminalColor.GREEN}{latest_version_tag}{TerminalColor.BLUE}]{TerminalColor.RESET}")
        print(f"{get_output_prefix()} {TerminalColor.BLUE}Download at: {TerminalColor.GREEN}https://github.com/0vm/NetDeflect{TerminalColor.RESET}")
        print("=" * 80)
        return True
    return False

# Load attack vector definitions
class AttackVectors:
    attack_signatures = {}
    attack_readable_names = {}
    
    @classmethod
    def load_vectors(cls):
        try:
            methods_file_path = "methods.json"
            with open(methods_file_path, 'r') as file:
                data = json.load(file)
                # Extract attack classifications
                cls.attack_signatures = data["attack_types"]
                cls.attack_readable_names = data["attack_types_readable"]
                return True
        except Exception:
            print(f"{get_output_prefix()} Failed to load methods, make sure to have methods.json in the same directory!")
            return False

def identify_malicious_ips_by_signature(capture_file):
    # Identify IPs that match known attack signatures
    malicious_ips = set()
    
    # For each attack signature, find IPs sending packets matching that signature
    for signature in AttackVectors.attack_signatures:
        pattern = AttackVectors.attack_signatures[signature]
        
        # Extract IPs sending packets that match this signature
        # The filter expression will depend on what exactly is in your signature patterns
        signature_filter = f"frame contains \"{pattern}\""
        matching_ips = subprocess.getoutput(f'sudo tshark -r {capture_file} -Y "{signature_filter}" -T fields -e ip.src | sort | uniq')
        
        # Add these IPs to our malicious set
        for ip in matching_ips.strip().split('\n'):
            if ip.strip():
                malicious_ips.add(ip.strip())
    
    return list(malicious_ips)

# Get network statistics
def get_network_stats():
    # Collect initial network stats
    bytes_initial = round(int(psutil.net_io_counters().bytes_recv) / 1024 / 1024, 3)
    packets_initial = int(psutil.net_io_counters().packets_recv)

    # Wait for next sample
    time.sleep(1)

    # Collect updated network stats
    packets_current = int(psutil.net_io_counters().packets_recv)
    bytes_current = round(int(psutil.net_io_counters().bytes_recv) / 1024 / 1024, 3)

    # Calculate network statistics
    pps = packets_current - packets_initial
    mbps = round(bytes_current - bytes_initial)
    cpu_usage = f"{int(round(psutil.cpu_percent()))}%"
    
    return pps, mbps, cpu_usage

# Display current network status
def display_network_stats(pps, mbps, cpu_usage):
    showed_update = display_update_notification()
    print(f"{get_output_prefix()}           IP Address: {TerminalColor.LIGHT_WHITE}[{TerminalColor.RED}{system_ip}{TerminalColor.LIGHT_WHITE}]{TerminalColor.RESET}")
    print(f"{get_output_prefix()}                  CPU: {TerminalColor.LIGHT_WHITE}[{TerminalColor.RED}{cpu_usage}{TerminalColor.LIGHT_WHITE}]{TerminalColor.RESET}")
    print(f"{get_output_prefix()}                 MB/s: {TerminalColor.LIGHT_WHITE}[{TerminalColor.RED}{mbps}{TerminalColor.LIGHT_WHITE}]{TerminalColor.RESET}")
    print(f"{get_output_prefix()}   Packets Per Second: {TerminalColor.LIGHT_WHITE}[{TerminalColor.RED}{pps}{TerminalColor.LIGHT_WHITE}]{TerminalColor.RESET}")
    return showed_update

# Clear previous output lines
def clear_lines(count=5):
    global update_available
    
    # Add extra lines if update notification is shown
    if update_available:
        count += 6  # Banner has 6 lines (separator + 4 content lines + separator)
    
    for i in range(count):
        sys.stdout.write('\x1b[1A')
        sys.stdout.write('\x1b[2K')

# Check if attack thresholds are exceeded
def is_under_attack(pps, mbps):
    if trigger_mode == "MP":
        return pps > pps_threshold and mbps > mbps_threshold
    elif trigger_mode == "P":
        return pps > pps_threshold
    elif trigger_mode == "M":
        return mbps > mbps_threshold
    return False

# Capture and analyze network traffic
def capture_and_analyze_traffic():
    try:
        # Initialize variables with default values
        capture_file = f"./application_data/captures/traffic.{get_timestamp()}.pcap"
        unique_ip_file = f"./application_data/ips/unique.{get_timestamp()}.txt"
        attack_data = ""
        target_port = "unknown"
        malicious_ips = []
        
        # Use subprocess.run with timeout instead of getoutput
        try:
            cmd = f'sudo tcpdump "{filter_arguments}" -i {network_interface} -n -s0 -c {packet_count} -w {capture_file}'
            process = subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        except subprocess.TimeoutExpired:
            print(f"{get_output_prefix()} tcpdump timed out after 30 seconds, continuing with analysis...")
        
        # Check if the capture file exists and has content
        if not os.path.exists(capture_file) or os.path.getsize(capture_file) == 0:
            print(f"{get_output_prefix()} No traffic captured or file not created")
            return capture_file, unique_ip_file, attack_data, target_port, malicious_ips

        # Extract attack pattern data
        try:
            cmd = f'sudo tshark -r {capture_file} -T fields -E header=y -e ip.proto -e tcp.flags -e udp.srcport -e tcp.srcport -e data'
            process = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            if process.returncode != 0:
                print(f"{get_output_prefix()} Error running tshark for attack data")
                return capture_file, unique_ip_file, attack_data, target_port, malicious_ips
            
            attack_data = process.stdout
        except Exception as e:
            print(f"{get_output_prefix()} Error running tshark for attack data: {str(e)}")
            return capture_file, unique_ip_file, attack_data, target_port, malicious_ips
        
        # Extract target port information
        try:
            cmd = f'sudo tshark -r {capture_file} -T fields -E header=y -e tcp.dstport -e udp.dstport'
            process = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            if process.returncode == 0:
                target_port_data = process.stdout
                port_lines = target_port_data.strip().split('\n')
                target_port = port_lines[1].strip() if len(port_lines) > 1 else "unknown"
        except Exception:
            target_port = "unknown"
        
        # Analyze attack type
        try:
            attack_type, attack_type_readable, notification_attack_type = analyze_attack_type(attack_data)
        except Exception as e:
            print(f"{get_output_prefix()} Error analyzing attack type: {str(e)}")
            attack_type = f"{TerminalColor.BLUE}[{TerminalColor.RED}Unclassified{TerminalColor.BLUE}]{TerminalColor.RESET}"
            attack_type_readable = "[Unclassified]"
            notification_attack_type = "[Unclassified]"
        
        # Only process if we have identified attack signatures
        if attack_type and "Unclassified" not in attack_type:
            try:
                # Find the signatures that were detected
                detected_signatures = []
                for signature in AttackVectors.attack_signatures:
                    # Clean up the signature from color codes
                    plain_signature = signature.replace('\u001b[34m', '').replace('\u001b[91m', '')
                    if plain_signature in attack_type:
                        pattern = AttackVectors.attack_signatures[signature]
                        detected_signatures.append((plain_signature, pattern))
                
                # Handle each detected attack signature
                for signature_name, pattern in detected_signatures:
                    print(f"{get_output_prefix()} Looking for pattern match: {signature_name} -> {pattern}")
                    matched_ips = []
                    
                    # Build filter based on pattern type
                    if pattern.startswith("0x"):
                        # TCP Flags
                        cmd = f'sudo tshark -r {capture_file} -Y "tcp.flags == {pattern}" -T fields -e ip.src | sort | uniq'
                    elif "," in pattern:
                        # Protocol combinations
                        proto_nums = pattern.split(",")[0].strip()
                        cmd = f'sudo tshark -r {capture_file} -Y "ip.proto == {proto_nums}" -T fields -e ip.src | sort | uniq'
                    elif "\t\t" in pattern:
                        # Protocol/port combinations
                        parts = pattern.split("\t\t")
                        proto_num = parts[0].strip()
                        port = parts[1].strip() if len(parts) > 1 else ""
                        
                        if port:
                            cmd = f'sudo tshark -r {capture_file} -Y "ip.proto == {proto_num} and (tcp.port == {port} or udp.port == {port})" -T fields -e ip.src | sort | uniq'
                        else:
                            cmd = f'sudo tshark -r {capture_file} -Y "ip.proto == {proto_num}" -T fields -e ip.src | sort | uniq'
                    else:
                        # Data pattern - try a few different approaches
                        cmd = f'sudo tshark -r {capture_file} -T fields -e ip.src -e data | grep -i {pattern} | cut -f1 | sort | uniq'
                    
                    # Run the command to match IPs
                    try:
                        process = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                        
                        if process.returncode == 0 and process.stdout.strip():
                            # Process matched IPs
                            for ip in process.stdout.strip().split('\n'):
                                if ip.strip() and re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip.strip()):
                                    # Make sure it's not our own IP or in trusted list
                                    if ip.strip() != system_ip and ip.strip() not in trusted_ips:
                                        print(f"{get_output_prefix()} Confirmed {ip.strip()} matched attack signature: {signature_name}")
                                        if ip.strip() not in malicious_ips:
                                            malicious_ips.append(ip.strip())
                    except Exception as e:
                        print(f"{get_output_prefix()} Error matching IPs for {signature_name}: {str(e)}")
                
                # If we found data-pattern attacks but no IPs, try an alternate approach ONLY if fallback enabled
                if not malicious_ips and any(not pattern.startswith("0x") and "," not in pattern and "\t\t" not in pattern for _, pattern in detected_signatures) and enable_fallback_blocking:
                    try:
                        # Get top traffic contributors
                        cmd = f'sudo tshark -r {capture_file} -T fields -e ip.src | sort | uniq -c | sort -nr | head -5'
                        process = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                        
                        if process.returncode == 0 and process.stdout.strip():
                            top_ips = []
                            
                            # Extract top IPs with counts
                            for line in process.stdout.strip().split('\n'):
                                if line.strip():
                                    parts = line.strip().split()
                                    if len(parts) >= 2:
                                        try:
                                            count = int(parts[0])
                                            ip = parts[1]
                                            
                                            # Only consider high volume and valid IPs
                                            if count > (packet_count / 5) and re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
                                                if ip != system_ip and ip not in trusted_ips:
                                                    top_ips.append((ip, count))
                                        except (ValueError, IndexError):
                                            continue
                            
                            # If we have top IPs, use the highest volume one
                            if top_ips:
                                top_ip, count = top_ips[0]
                                percent = (count * 100) / packet_count
                                
                                # Only use this fallback if the IP dominates traffic
                                if percent > 30:  # More than 30% of packets
                                    print(f"{get_output_prefix()} Data signature match failed, using top contributor: {top_ip} ({percent:.1f}% of traffic)")
                                    malicious_ips.append(top_ip)
                    except Exception as e:
                        print(f"{get_output_prefix()} Error in alternate IP detection: {str(e)}")
            except Exception as e:
                print(f"{get_output_prefix()} Error in signature-based IP detection: {str(e)}")
        
        # Save the malicious IPs to file
        try:
            with open(unique_ip_file, 'w') as f:
                for ip in malicious_ips:
                    f.write(f"{ip}\n")
        except Exception as e:
            print(f"{get_output_prefix()} Error saving IP list: {str(e)}")
        
        return capture_file, unique_ip_file, attack_data, target_port, malicious_ips
    except Exception as e:
        print(f"{get_output_prefix()} Error in traffic capture: {str(e)}")
        empty_file = f"./application_data/ips/empty.{get_timestamp()}.txt"
        try:
            open(empty_file, 'w').close()
        except:
            pass
        return "", empty_file, "", "unknown", []

def analyze_attack_type(packet_data):
    # Initialize attack classification variables
    attack_type = ''
    attack_type_readable = ''
    notification_attack_type = ''

    # Clean up packet data - remove any lines that aren't actual packet data
    cleaned_data = []
    for line in packet_data.split('\n'):
        if not line.startswith('Running') and line.strip():
            cleaned_data.append(line)
    
    packet_data = '\n'.join(cleaned_data)

    # Debug output of what's being searched
    print(f"{get_output_prefix()} Debug: Analyzing {len(packet_data)} bytes of packet data")
    
    matching_signatures = []
    
    # Analyze packet patterns
    for signature in AttackVectors.attack_signatures:
        try:
            # Convert to a plain string without color codes - we need to check actual content
            plain_signature = signature.replace('\u001b[34m', '').replace('\u001b[91m', '')
            pattern = AttackVectors.attack_signatures[signature]
            
            # Count signature occurrences
            match_count = packet_data.count(pattern)
            
            # Debug output for each signature check
            if match_count > 0:
                print(f"{get_output_prefix()} Debug: Found {match_count} matches for {plain_signature}")

            # Check if threshold met
            if match_count > detection_threshold:
                # Calculate percentage of matching packets - be careful with division
                percentage = min(100.0, (100.0 * float(match_count) / float(packet_count)))
                
                # Add to matching signatures list
                matching_signatures.append((plain_signature, percentage))
                
                # Build attack classification string
                attack_type += f"{plain_signature} ({percentage:.2f}%)]"
        except Exception as e:
            print(f"{get_output_prefix()} Error analyzing signature {signature}: {str(e)}")

    # Analyze for human-readable classifications
    readable_matching_signatures = []
    for signature in AttackVectors.attack_readable_names:
        try:
            pattern = AttackVectors.attack_readable_names[signature]
            
            # Count occurrences
            match_count = packet_data.count(pattern)
            
            # Debug output for each signature check
            if match_count > 0:
                print(f"{get_output_prefix()} Debug: Found {match_count} readable matches for {signature}")

            # Check if threshold met
            if match_count > detection_threshold:
                # Calculate percentage - capped at 100%
                percentage = min(100.0, (100.0 * float(match_count) / float(packet_count)))
                
                # Add to readable matches list
                readable_matching_signatures.append((signature, percentage))
                
                # Set readable classification
                attack_type_readable += f"{signature}]"
                notification_attack_type += f"{signature} ({percentage:.2f}%)]"
        except Exception as e:
            print(f"{get_output_prefix()} Error analyzing readable signature {signature}: {str(e)}")

    # Handle unclassified attacks
    if not matching_signatures:
        attack_type = f"{TerminalColor.BLUE}[{TerminalColor.RED}Unclassified{TerminalColor.BLUE}]{TerminalColor.RESET}"
    
    if not readable_matching_signatures:
        attack_type_readable = f"[Unclassified]"
    
    # Print what we found
    if matching_signatures:
        print(f"{get_output_prefix()} Found attack signatures: {', '.join([s[0] for s in matching_signatures])}")
    
    return attack_type, attack_type_readable, notification_attack_type

# Block IPs found in attack
def block_malicious_ips(unique_ip_file):
    global blocked_ips
    
    # Read malicious IP list
    with open(unique_ip_file) as file:
        ip_list = [line.strip() for line in file.readlines() if line.strip()]

    # Count unique IPs
    total_ips = len(ip_list)
    blocked_count = 0
    actual_blocked = []

    # Process each IP
    for ip_address in ip_list:
        if block_ip(ip_address):
            blocked_count += 1
            actual_blocked.append(ip_address)

    return total_ips, blocked_count, actual_blocked

# Evaluate mitigation effectiveness
def evaluate_mitigation(pps, mbps):
    if pps < pps_threshold and mbps < mbps_threshold:
        print(f"{get_output_prefix()}       {TerminalColor.RED}Traffic volume: {TerminalColor.BLUE}[   {TerminalColor.GREEN}Decreased   {TerminalColor.BLUE}]{TerminalColor.RESET}")
        print(f"{get_output_prefix()}        {TerminalColor.RED}Attack Status: {TerminalColor.BLUE}[   {TerminalColor.GREEN} Mitigated  {TerminalColor.BLUE}]{TerminalColor.RESET}")
        return "Decreased (mitigated)"
    elif (pps > pps_threshold and mbps < mbps_threshold) or (pps < pps_threshold and mbps > mbps_threshold):
        print(f"{get_output_prefix()}       {TerminalColor.RED}Traffic volume: {TerminalColor.BLUE}[   {TerminalColor.GREEN}Decreased   {TerminalColor.BLUE}]{TerminalColor.RESET}")
        print(f"{get_output_prefix()}        {TerminalColor.RED}Attack Status: {TerminalColor.BLUE}[   {TerminalColor.GREEN}Partially Mitigated{TerminalColor.BLUE}]{TerminalColor.RESET}")
        return "Decreased (partially mitigated)"
    else:
        print(f"{get_output_prefix()}       {TerminalColor.RED}Traffic volume: {TerminalColor.BLUE}[   {TerminalColor.RED}Increased   {TerminalColor.BLUE}]{TerminalColor.RESET}")
        print(f"{get_output_prefix()}        {TerminalColor.RED}Attack Status: {TerminalColor.BLUE}[   {TerminalColor.RED}Ongoing    {TerminalColor.BLUE}]{TerminalColor.RESET}")
        return "Ongoing Attack"

# Send notification webhook
def send_notification(notification_template, attack_id, pps, mbps, cpu_usage, status, total_ips, attack_type_readable):
    report_path = f"**./application_data/attack_analysis/{get_timestamp()}.txt**"
    notification_json = json.dumps(notification_template)
    notification_json = notification_json.replace("{{attack_id}}", str(attack_id))
    notification_json = notification_json.replace("{{pps}}", str(pps))
    notification_json = notification_json.replace("{{mbps}}", str(mbps))
    notification_json = notification_json.replace("{{cpu}}", str(cpu_usage))
    notification_json = notification_json.replace("{{status}}", str(status))
    notification_json = notification_json.replace("{{block_count}}", str(total_ips))
    notification_json = notification_json.replace("{{report_file}}", str(report_path))
    notification_json = notification_json.replace("{{attack_vector}}", str(attack_type_readable))

    try:
        headers = {'content-type': 'application/json'}
        requests.post(webhook_url, notification_json, headers=headers, timeout=3)
        print(f"{get_output_prefix()} {TerminalColor.RED}Notification Status: {TerminalColor.BLUE}[{TerminalColor.RED}    Sent    {TerminalColor.BLUE}]{TerminalColor.RESET}")
        return True
    except Exception:
        print(f"{get_output_prefix()} {TerminalColor.RED}Notification Status: {TerminalColor.BLUE}[{TerminalColor.RED}    Failed    {TerminalColor.BLUE}]{TerminalColor.RESET}")
        return False

def main():
    global blocked_ips
    start_update_checker()
    # Load notification template
    try:
        with open('notification_template.json', 'r', encoding='utf-8') as webhook:
            notification_template = json.load(webhook)
    except:
        # Default notification template
        default_template = {
        "content": None,
        "embeds": [
            {
                "title": "⚠️ DDoS Attack Mitigated: #{{attack_id}}",
                "description": "NetDeflect detected and responded to a potential attack.",
                "url": "https://github.com/0vm/NetDeflect",
                "color": 16734296,
                "fields": [
                    {
                        "name": "📊 Pre-Mitigation Stats",
                        "value": (
                            "• **Packets/s (PPS):** {{pps}}\n"
                            "• **Megabytes/s (MBPS):** {{mbps}}\n"
                            "• **CPU Usage:** {{cpu}}"
                        ),
                        "inline": False
                    },
                    {
                        "name": "🛡️ Post-Mitigation Results",
                        "value": (
                            "• **Status:** {{status}}\n"
                            "• **IPs Blocked:** {{block_count}}\n"
                            "• **Attack Type:** {{attack_vector}}"
                        ),
                        "inline": False
                    },
                    {
                        "name": "📁 Analysis Report",
                        "value": "{{report_file}}",
                        "inline": True
                    }
                ],
                "author": {
                    "name": "NetDeflect",
                    "icon_url": "https://avatars.githubusercontent.com/u/79897291?s=96&v=4"
                },
                "footer": {
                    "text": "github.com/0vm/NetDeflect",
                    "icon_url": "https://github.githubassets.com/assets/GitHub-Mark-ea2971cee799.png"
                }
            }
        ]
    }
        
        with open('notification_template.json', 'w', encoding='utf-8') as f:
            json.dump(default_template, f, ensure_ascii=False, indent=4)

        # Inform user
        print(f"{get_output_prefix()} notification_template.json creation failed")
        print(f"{get_output_prefix()} notification_template.json has been reset")
        print(f"{get_output_prefix()} Please update notification_template.json with your custom notification format.")

        # Exit application
        exit()

    # Main monitoring loop
    while True:
        try:
            # Get current network stats
            pps, mbps, cpu_usage = get_network_stats()
            
            # Display current network status
            display_network_stats(pps, mbps, cpu_usage)

            # Clear previous lines for clean output
            clear_lines()

        except Exception as e:
            print(e)
            exit()

        # Check for attack conditions
        if is_under_attack(pps, mbps):
            # Display current network stats again (without clearing)
            display_network_stats(pps, mbps, cpu_usage)
        
            # Alert user of threshold breach
            print(f"{get_output_prefix()}   {TerminalColor.RED}    Limit Exceeded: {TerminalColor.WHITE}[{TerminalColor.GREEN}MITIGATION ACTIVE{TerminalColor.WHITE}]{TerminalColor.RESET}")
            
            try:
                # Capture and analyze traffic
                capture_file, unique_ip_file, attack_data, target_port, malicious_ips = capture_and_analyze_traffic()
                
                # Make sure we have valid data before proceeding
                if not capture_file or not attack_data:
                    print(f"{get_output_prefix()} Failed to capture traffic data, skipping this detection cycle.")
                    time.sleep(mitigation_pause)
                    continue
                
                # Analyze attack type
                attack_type, attack_type_readable, notification_attack_type = analyze_attack_type(attack_data)
                
                # Display attack classification
                print(f"{get_output_prefix()} Detected attack type: {attack_type}")
                
                # Block malicious IPs
                total_ips = len(malicious_ips)
                blocked_count = 0
                actual_blocked = []
                
                for ip_address in malicious_ips:
                    if block_ip(ip_address):
                        blocked_count += 1
                        actual_blocked.append(ip_address)
                
                # Brief pause for clean output
                time.sleep(1)
                
                # Format the list of IPs for reporting
                detected_ips = ' '.join(malicious_ips)
                
                # Get post-mitigation stats
                pps_after, mbps_after, cpu_after = get_network_stats()
                
                # Display attack classification again
                print(f"{get_output_prefix()} Detected attack type: {attack_type}")
                
                # Evaluate mitigation effectiveness
                attack_status = evaluate_mitigation(pps_after, mbps_after)
                
                # Generate attack ID
                attack_id = len(os.listdir("./application_data/captures"))
                
                # Generate analysis report
                analysis_report = f"""-----   Analysis Report: {get_timestamp()}   -----
        Pre-Mitigation:
          • Packets Per Second: {pps}
          • Megabytes Per Second: {mbps}
          • CPU Utilization: {cpu_usage}
        
        Post-Mitigation:
          • Packets Per Second: {pps_after}
          • Megabytes Per Second: {mbps_after}
          • CPU Utilization: {cpu_after}
        
        Details:
          • IPs Detected: {total_ips}
          • IPs Found: {detected_ips}
          • IPs Blocked: {', '.join(actual_blocked) if actual_blocked else "None"} 
          • Attack Type: {attack_type_readable}
          • Target Port: {target_port}
          • Target IP: {system_ip}
        
        Status:
          • Mitigation Status: {attack_status}"""
                
                try:
                    # Save analysis report
                    with open(f"./application_data/attack_analysis/{get_timestamp()}.txt", "w") as report_file:
                        report_file.write(analysis_report)
                except Exception as e:
                    print(f"{get_output_prefix()} Failed to save analysis report: {str(e)}")
                
                # Send notification
                send_notification(notification_template, attack_id, pps, mbps, cpu_usage, attack_status, total_ips, attack_type_readable)
                
                # Pause before next scan
                print(f"{get_output_prefix()} {TerminalColor.RED}Pausing Mitigation for: {TerminalColor.WHITE}[{TerminalColor.RED}   {mitigation_pause} seconds  {TerminalColor.WHITE}]{TerminalColor.RESET}")
                
                # Clear blocked IPs list for next run
                blocked_ips = []
                
                # Pause before next detection cycle
                time.sleep(mitigation_pause)
                
            except Exception as e:
                print(f"{get_output_prefix()} Error during attack handling: {str(e)}")
                print(f"{get_output_prefix()} Pausing before next detection cycle")
                time.sleep(mitigation_pause)

dir()

# Load attack vectors
if not AttackVectors.load_vectors():
    exit()

# Init ipset if needed
if firewall_system == 'ipset':
    configure_ipset()

# Start monitoring
main()
