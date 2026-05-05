import smtplib
from email.mime.text import MIMEText

ALERT_LOG = 'alert.log'

# Replace these with real values and load from environment variables in production.
EMAIL_ADDRESS  = 'abc@gmail.com'
EMAIL_PASSWORD = 'your_password'
EMAIL_TO       = '123@gmail.com'
SMTP_SERVER    = 'smtp.gmail.com'
SMTP_PORT      = 587


def run_alert(msg, localtime, protocol, src, dst, sport, dport):
    """Append a formatted alert entry to alert.log."""
    entry = (
        f"{msg}\n"
        f"Time: {localtime}, Protocol: {protocol}, "
        f"Src: {src}:{sport}, Dst: {dst}:{dport}\n\n"
    )
    with open(ALERT_LOG, 'a') as f:
        f.write(entry)


def send_alert_email(rule, matched_values):
    """Send an SMTP email alert for a matched rule."""
    if 'Options' not in rule:
        print("Rule missing 'Options' key — skipping email.")
        return

    content_str = ', '.join(matched_values)
    body = (
        f"Packet content matched for rule: {rule['Options']}\n"
        f"Matched content: {content_str}"
    )
    msg = MIMEText(body)
    msg['Subject'] = f"IDS Alert: rule matched — {rule.get('Available Option Values', {}).get('msg', '')}"
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = EMAIL_TO

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.sendmail(EMAIL_ADDRESS, EMAIL_TO, msg.as_string())
    except Exception as e:
        print(f"Failed to send email alert: {e}")
