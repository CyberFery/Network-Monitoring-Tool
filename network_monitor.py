import smtplib
from scapy.all import sniff, IP
from datetime import datetime

# Configuration
LOG_FILE = "network_traffic.log"
ALERT_THRESHOLD = 1000  # Number of packets to trigger an alert
EMAIL_FROM = "your_email@example.com"
EMAIL_TO = "recipient@example.com"
EMAIL_PASSWORD = "your_email_password"
SMTP_SERVER = "smtp.example.com"
SMTP_PORT = 587

# Global counter for packets
packet_count = 0

def log_packet(packet):
    """
    Logs packet details to a file.
    """
    global packet_count
    packet_count += 1

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        log_entry = f"{timestamp} | Source: {src_ip} | Destination: {dst_ip} | Protocol: {protocol}\n"
        with open(LOG_FILE, "a") as log_file:
            log_file.write(log_entry)

        # Check if alert threshold is reached
        if packet_count >= ALERT_THRESHOLD:
            send_alert()

def send_alert():
    """
    Sends an email alert when suspicious activity is detected.
    """
    global packet_count
    subject = "Network Traffic Alert"
    body = f"Suspicious network activity detected! Total packets: {packet_count}"

    message = f"Subject: {subject}\n\n{body}"

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_FROM, EMAIL_PASSWORD)
            server.sendmail(EMAIL_FROM, EMAIL_TO, message)
        print("Alert email sent successfully!")
    except Exception as e:
        print(f"Failed to send alert email: {e}")

def start_monitoring(interface="eth0"):
    """
    Starts monitoring network traffic on the specified interface.
    """
    print(f"Starting network monitoring on interface {interface}...")
    sniff(iface=interface, prn=log_packet)

if __name__ == "__main__":
    start_monitoring()
