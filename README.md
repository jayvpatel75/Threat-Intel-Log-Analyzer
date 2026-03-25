# Threat-Intel-Log-Analyzer

> A Python-based Blue Team security automation project that analyzes web server logs, detects suspicious IP activity, enriches indicators with VirusTotal, updates a firewall-ready blocklist, and sends real-time Slack or Discord alerts.

---

## Project Overview

**Threat-Intel-Log-Analyzer** is a security automation tool built for Blue Team and SOC-style workflows. It helps identify suspicious IP addresses from raw web server logs, checks their reputation using the **VirusTotal API**, and automates response actions such as blocklisting and alerting.

This project demonstrates practical skills in:

- Python scripting
- Log analysis
- Threat intelligence enrichment
- Security automation
- API integration
- Webhook-based alerting

---

## Features

- Parses raw web server logs
- Detects suspicious IPs based on repeated activity
- Queries the VirusTotal API for IP reputation
- Automatically appends malicious IPs to a blocklist CSV
- Sends real-time alerts to **Slack** or **Discord**
- Uses environment variables for secure configuration
- Simple and portfolio-friendly project structure

---

## Project Structure

```text
Threat-Intel-Log-Analyzer/
├── .env.example
├── .gitignore
├── README.md
├── requirements.txt
├── sample_logs.txt
└── src/
    └── threat_analyzer.py
```

## How It Works

The workflow is simple and effective:

Read IP addresses from the input log file
Count how many times each IP appears
Flag IPs that exceed the suspicious activity threshold
Query VirusTotal for threat intelligence
If an IP is malicious:
Add it to blocked_ips.csv
Send an alert to Slack or Discord

## Tech Stack
Python 3
requests
python-dotenv
VirusTotal API
Slack Webhooks
Discord Webhooks

## Installation
1. Clone the repository
``` bash
git clone https://github.com/your-username/Threat-Intel-Log-Analyzer.git
cd Threat-Intel-Log-Analyzer
```

2. Create a virtual environment

Windows
``` bash
python -m venv venv
venv\Scripts\activate
```

Mac/Linux
``` bash
python3 -m venv venv
source venv/bin/activate
```

3. Install dependencies

``` bash
pip install -r requirements.txt
```
## Configuration

Create a .env file in the project root using .env.example as a template.

VIRUSTOTAL_API_KEY=your_actual_api_key_here
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL

