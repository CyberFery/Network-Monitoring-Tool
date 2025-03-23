# Network Monitoring Tool

A Python-based tool for monitoring network traffic, logging packet details, and sending email alerts for suspicious activity.

## Features
- **Packet Sniffing:** Captures and logs network traffic (source IP, destination IP, protocol, timestamp).
- **Email Alerts:** Sends alerts when packet count exceeds a predefined threshold.
- **Logging:** Stores network traffic details in a log file for analysis.

## Requirements
- Python 3.x
- scapy (`pip install scapy`)

## Usage
1. Clone the repository:
   ```bash
   git clone https://github.com/CyberFery/NetworkMonitor.git
   cd NetworkMonitor
Configure email settings in network_monitor.py:
```python
EMAIL_FROM = "your_email@example.com"
EMAIL_TO = "recipient@example.com"
EMAIL_PASSWORD = "your_email_password"
SMTP_SERVER = "smtp.example.com"
SMTP_PORT = 587
```

Run the script:
```bash
python network_monitor.py
```
## 
