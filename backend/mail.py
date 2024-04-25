from django.core.mail import send_mail
from django.conf import settings

def sending_mail(request,subject,message,to_email):
    subject = subject #'Hello'
    message = message #'This is a test email.'
    from_email = settings.DEFAULT_FROM_EMAIL   # Your temporary email address
    recipient_list = [to_email]  # Recipient's email address

    try:
        res = send_mail(subject, message, from_email, recipient_list)
        print(res)
        return True
    except Exception as e:
        print(e)
        return False