import requests
import os
import json
from log_parser import parse_cowrie_logs  # Import your log parser

# Load API Key from environment variable
API_KEY = "597a45ad837b3b01f18c40f2a04d1b895115b43675985fdecef05790afe8e39ec81701bdef810775"

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

def check_abuseipdb(ip):
    """ Check if an IP is listed in AbuseIPDB """
    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(ABUSEIPDB_URL, headers=headers, params=params)
        response.raise_for_status()  # Raise error for bad responses (e.g., 403, 500)
        data = response.json()
        
        return {
            "IP": data['data']['ipAddress'],
            "Abuse Score": data['data']['abuseConfidenceScore'],
            "ISP": data['data']['isp'],
            "Domain": data['data']['domain'],
            "Usage Type": data['data']['usageType']
        }

    except requests.exceptions.RequestException as e:
        print(f"Error checking AbuseIPDB: {e}")
        return None


if __name__ == "__main__":
    # Get attacker IPs from logs
    log_file = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
    attackers = parse_cowrie_logs(log_file)

    if not attackers:
        print("No attackers found in logs.")
        exit()

    print("\n🔎 Checking IPs in AbuseIPDB...\n")
    
    for attacker in attackers:
        ip = attacker["IP"]
        result = check_abuseipdb(ip)

        if result:
            print(f"⚠️ IP: {result['IP']} | Abuse Score: {result['Abuse Score']}% | ISP: {result['ISP']} | Domain: {result['Domain']}")
            
            # Flag high-risk attackers (Abuse Score > 50%)
            if result["Abuse Score"] > 50:
                print(f"🚨 HIGH-RISK ATTACKER DETECTED: {result['IP']} (Abuse Score: {result['Abuse Score']}%)\n")

        else:
            print(f"❌ Failed to fetch data for {ip}")

    print("\n✅ AbuseIPDB scan complete!")
