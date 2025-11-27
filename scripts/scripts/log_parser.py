import json
import os
from collections import defaultdict

# Path to store attacker IPs
ATTACKER_IP_FILE = "/home/cowrie/scripts/attacker_ips.txt"

LOG_FILE = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"

# Common attack tools to detect
TOOL_KEYWORDS = ["putty", "nmap", "hydra", "sqlmap", "metasploit", "nikto", "wfetch", "curl", "wget"]

# Store occurrences of each IP (for redundancy filtering)
ip_occurrences = defaultdict(int)
MAX_OCCURRENCES = 1  # Allow max 10 logs per unique IP

def parse_cowrie_logs():
    """Extracts attack details from Cowrie logs and returns them as a list."""
    attackers = []

    try:
        with open(LOG_FILE, 'r') as f:
            for line in f:
                try:
                    log_entry = json.loads(line)

                    ip = log_entry.get('src_ip')
                    event_type = log_entry.get('eventid', '')
                    timestamp = log_entry.get('timestamp', '')
                    session_id = log_entry.get('session', '')
                    username = log_entry.get('username', 'Unknown')
                    password = log_entry.get('password', 'Unknown')
                    command = log_entry.get('input', '')
                    downloaded_file = log_entry.get('outfile', '')

                    # Skip if IP is missing or exceeds redundancy threshold
                    if not ip or ip_occurrences[ip] >= MAX_OCCURRENCES:
                        continue
                    
                    ip_occurrences[ip] += 1  # Track occurrences

                    # Detect attack tools
                    detected_tools = [tool for tool in TOOL_KEYWORDS if tool in command.lower()]
                    detected_tools = detected_tools if detected_tools else ["unknown tool"]

                    # Store useful attack information
                    attack_info = {
                        "IP": ip,
                        "Timestamp": timestamp,
                        "Session ID": session_id,
                        "Event Type": event_type,
                        "Username": username,
                        "Password": password,
                        "Commands": command.strip() if command else "N/A",
                        "Tools Detected": detected_tools,
                        "Downloaded File": downloaded_file if downloaded_file else "None"
                    }

                    attackers.append(attack_info)

                except json.JSONDecodeError:
                    continue

    except FileNotFoundError:
        print(f"Error: Log file not found at {LOG_FILE}")
        return []
    except PermissionError:
        print(f"Error: Permission denied for {LOG_FILE}")
        return []

    return attackers

if __name__ == "__main__":
    parsed_data = parse_cowrie_logs()
    print(json.dumps(parsed_data, indent=4))
