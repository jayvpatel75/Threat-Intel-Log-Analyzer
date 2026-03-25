import re
import requests
import time
import os
from dotenv import load_dotenv

load_dotenv()

# --- CONFIGURATION ---
API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
SLACK_WEBHOOK = os.environ.get("SLACK_WEBHOOK_URL")

LOG_FILE = "../sample_logs.txt"
BLOCKLIST_FILE = "../blocked_ips.csv"
THRESHOLD = 5
REQUEST_TIMEOUT = 15

def extract_ips_from_log(file_path):
    """Reads a log file and returns a dictionary of IP frequencies."""
    ip_pattern = r"\d{1,3}(?:\.\d{1,3}){3}"
    ip_counts = {}

    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        absolute_file_path = os.path.join(script_dir, file_path)

        with open(absolute_file_path, "r", encoding="utf-8") as file:
            for line in file:
                if line.strip().startswith("#"):
                    continue

                matches = re.findall(ip_pattern, line)
                if matches:
                    ip = matches[0]
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1

        return ip_counts

    except FileNotFoundError:
        print(f"❌ Error: Could not find the log file at {file_path}")
        return {}
    except OSError as e:
        print(f"❌ Error reading log file: {e}")
        return {}

def check_virustotal(ip):
    """Queries the VirusTotal API and returns the number of malicious flags."""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)

        if response.status_code == 200:
            data = response.json()
            return data["data"]["attributes"]["last_analysis_stats"]["malicious"]

        print(f"⚠️ VirusTotal API error for {ip}: {response.status_code} - {response.text}")
        return 0

    except requests.exceptions.RequestException as e:
        print(f"⚠️ Network error while checking {ip}: {e}")
        return 0

def update_firewall(ip, count):
    """Appends the malicious IP to a CSV file for firewall consumption."""
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        absolute_blocklist_path = os.path.join(script_dir, BLOCKLIST_FILE)

        with open(absolute_blocklist_path, "a", encoding="utf-8") as firewall_file:
            firewall_file.write(f"{ip},{count}\n")

    except OSError as e:
        print(f"⚠️ Failed to update firewall blocklist for {ip}: {e}")

def send_slack_alert(ip, count):
    """Sends a formatted alert message to Slack via webhook."""
    if not SLACK_WEBHOOK or SLACK_WEBHOOK == "https://hooks.slack.com/services/YOUR/WEBHOOK/URL":
        print("⚠️ Slack webhook is not configured in .env")
        return False

    vt_link = f"https://www.virustotal.com/gui/ip-address/{ip}"

    alert_data = {
        "username": "Threat Intel Automator",
        "icon_emoji": ":rotating_light:",
        "text": (
            f"🚨 *SECURITY ALERT*\n"
            f"*Malicious IP Detected:* `{ip}`\n"
            f"*VirusTotal Malicious Flags:* `{count}`\n"
            f"*Action Taken:* Added to firewall blocklist\n"
            f"*Report:* <{vt_link}|View VirusTotal Report>"
        )
    }

    try:
        response = requests.post(
            SLACK_WEBHOOK,
            json=alert_data,
            timeout=REQUEST_TIMEOUT
        )

        if response.status_code == 200 and response.text.strip().lower() == "ok":
            print(f"📨 Slack alert sent for {ip}")
            return True

        print(f"⚠️ Slack webhook failed for {ip}: {response.status_code} - {response.text}")
        return False

    except requests.exceptions.RequestException as e:
        print(f"⚠️ Failed to send Slack alert for {ip}: {e}")
        return False

def main():
    if not API_KEY or API_KEY == "your_actual_api_key_here":
        print("❌ Error: Please add your VirusTotal API Key to the .env file!")
        return

    if not SLACK_WEBHOOK or SLACK_WEBHOOK == "https://hooks.slack.com/services/YOUR/WEBHOOK/URL":
        print("❌ Error: Please add your Slack webhook URL to the .env file!")
        return

    print(f"🔍 Starting Security Scan (Threshold: >{THRESHOLD} requests)...\n")

    ip_counts = extract_ips_from_log(LOG_FILE)
    if not ip_counts:
        return

    suspicious_ips = {ip: count for ip, count in ip_counts.items() if count > THRESHOLD}
    print(f"Found {len(suspicious_ips)} suspicious IP(s) exceeding threshold.\n")

    for ip in suspicious_ips:
        print(f"Checking {ip} with VirusTotal...")
        malicious_count = check_virustotal(ip)
        
        if malicious_count > 0:
            print(f"🚨 DANGER: {ip} is malicious ({malicious_count} flags). Mitigating...")
            update_firewall(ip, malicious_count)
            send_slack_alert(ip, malicious_count)
        else:
            print(f"✅ CLEAR: {ip} seems safe.")

        print("Sleeping for 15s to respect API rate limits...\n")
        time.sleep(15)

    print("🏁 Security Automation Pipeline Complete!")

if __name__ == "__main__":
    main()
