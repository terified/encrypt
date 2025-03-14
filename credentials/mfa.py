import random
import smtplib
from email.mime.text import MIMEText

def send_otp_via_email(email):
    otp = generate_otp()
    msg = MIMEText(f"Your OTP code is {otp}")
    msg['Subject'] = 'Your OTP Code'
    msg['From'] = 'no-reply@example.com'
    msg['To'] = email

    try:
        with smtplib.SMTP('smtp.example.com') as server:
            server.login('your_username', 'your_password')
            server.sendmail(msg['From'], [msg['To']], msg.as_string())
        print("OTP sent successfully.")
    except Exception as e:
        print(f"Failed to send OTP: {e}")

    return otp

def generate_otp():
    return str(random.randint(100000, 999999))

def verify_otp(user_otp, actual_otp):
    return user_otp == actual_otp