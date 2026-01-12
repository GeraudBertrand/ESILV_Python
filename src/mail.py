import smtplib
from email.mime.text import MIMEText
from typing import Optional


class Mail:
    """Simple SMTP mail sender. Provide `from_mail` and `password`.

    Example:
        m = Mail(to_mail='user@example.com', from_mail='me@host', password='pwd')
        m.send('Subject', 'Body text')
    """

    def __init__(
        self,
        from_mail: str,
        password: str,
        server: str = "smtp.gmail.com",
        port: int = 587,
    ):
        self.server_addr = server
        self.server_port = port
        self.from_mail = from_mail
        self.password = password

    def send(self, subject: str, body: str, to_email: str) -> bool:
        """Send an email. Returns True on success, False on error."""

        msg = MIMEText(body)
        msg["From"] = self.from_mail
        msg["To"] = to_email
        msg["Subject"] = subject

        try:
            server = smtplib.SMTP(self.server_addr, self.server_port, timeout=10)
            server.ehlo()
            server.starttls()
            server.login(self.from_mail, self.password)
            server.sendmail(self.from_mail, [to_email], msg.as_string())
            server.quit()
            return True
        except Exception as e:
            print(f"Erreur envoi mail vers {to_email}: {e}")
            return False
        
    def body_template(self) -> str :
        """
        Generate a body mail for notification of vulnerability
        """
        body = (
            "Une nouvelle vulnérabilité critique a été détectée:\n\n"
            "ID: {id_anssi}\n"
            "Titre: {title}\n"
            "Date: {date}\n"
            "CVE: {cve}\n"
            "CVSS: {cvss}\n"
            "Lien: {link}\n\n"
            "Description:\n{description}\n"
        )
        return body