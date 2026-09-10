"""Round-8 Email Header Injection fixture (smtplib + f-string headers)."""
import smtplib


def send_email(to_address, subject, message):
    """BAD: user-controlled values interpolated straight into mail headers."""
    server = smtplib.SMTP('localhost', 25)
    email_message = f"""From: noreply@example.com
To: {to_address}
Subject: {subject}

{message}
"""
    server.sendmail('noreply@example.com', to_address, email_message)
    server.quit()


def contact_form(request):
    """BAD: view passes request.POST values straight into send_email()."""
    email = request.POST.get('email')
    subject = request.POST.get('subject')
    message = request.POST.get('message')
    send_email(email, subject, message)
    return {'sent': True}


def send_email_safe(to_address, subject, message):
    """GOOD: static, non-interpolated message body (no header injection)."""
    server = smtplib.SMTP('localhost', 25)
    email_message = (
        "From: noreply@example.com\r\n"
        "To: fixed-recipient@example.com\r\n"
        "Subject: Welcome\r\n"
        "\r\n"
        "Body of the message."
    )
    server.sendmail('noreply@example.com', 'fixed-recipient@example.com', email_message)
    server.quit()
