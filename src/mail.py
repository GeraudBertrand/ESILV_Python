import smtplib
from email.mime.text import MIMEText


class Mail :

    server : smtplib.SMTP
    SERVER_MAIL = "smtp.gmail.com"
    SERVER_PORT = 587

    FROM_MAIL = ""
    PASSWORD = ""

    def __init__ (self, to_mail, from_mail=""):
        self.server = smtplib.SMTP(self.SERVER_MAIL, self.SERVER_PORT)
        if(len(from_mail) > 0) :
            self.FROM_MAIL = from_mail
        self.to = to_mail
    
    def send(self, to_email: str, subject: str, body:str):
        msg = MIMEText(body)
        msg['From'] = self.FROM_MAIL
        msg['To'] = to_email
        msg['Subject'] = subject

        self.server.starttls()
        self.server.login(self.FROM_MAIL, self.PASSWORD)
        self.server.sendmail(self.FROM_MAIL, to_email, msg.as_string())
        self.server.quit()