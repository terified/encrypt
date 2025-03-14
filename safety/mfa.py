import pyotp
import smtplib
from email.mime.text import MIMEText

def generate_totp_secret():
    return pyotp.random_base32()

def generate_totp_token(secret):
    totp = pyotp.TOTP(secret)
    return totp.now()

def verify_totp_token(secret, token):
    totp = pyotp.TOTP(secret)
    return totp.verify(token)

def send_otp_via_email(otp, recipient_email):
    sender_email = "your_email@example.com"
    sender_password = "your_email_password"
    smtp_server = "smtp.example.com"
    smtp_port = 587

    msg = MIMEText(f"Your OTP is: {otp}")
    msg['Subject'] = "Your OTP Code"
    msg['From'] = sender_email
    msg['To'] = recipient_email

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)

def send_otp_via_sms(otp, phone_number):
    # This function should integrate with an SMS gateway API
    # For example, using Twilio or another service
    pass