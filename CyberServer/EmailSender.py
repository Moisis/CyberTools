import os
import smtplib
from email.mime.text import MIMEText


def send_email(recipient_email, message_text):
    # print(f'message sent to {recipient_email}: ', message_text)
    sender_email = os.getenv("EMAIL_SERVICE_USER")
    sender_password = os.getenv("EMAIL_SERVICE_PASSWORD")
    smtp_server = os.getenv("EMAIL_SERVER")
    smtp_port = os.getenv("EMAIL_PORT")

    try:
        message_text = "Your registration code is " + message_text
        msg = MIMEText(message_text)
        msg['Subject'] = "Cybertools Registration Code"
        msg['From'] = sender_email
        msg['To'] = recipient_email

        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)
            print("Email sent successfully!")
            return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False

