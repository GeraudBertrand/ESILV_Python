import smtplib
from email.mime.text import MIMEText
from typing import Optional, Any
from pandas import Series


class Mail:
    """Simple classe pour envoyer des emails via SMTP. 
    Accessible pour Gmail en utilisant les identifiants d'application dans le fichier .env

    port : 587 - port TLS / 465 - port SSL

    Example:
        m = Mail(to_mail='user@example.com', from_mail='me@host', password='pwd')
        m.send('Subject', 'Body text')

    Args:
        from_mail (str): Adresse e-mail de l'expéditeur.
        password (str): Mot de passe de l'e-mail de l'expéditeur.
        server (str, optional): Adresse du serveur SMTP. Par défaut "smtp.gmail.com".
        port (int, optional): Port du serveur SMTP. Par défaut 465 (SSL).
    """

    def __init__(
        self,
        from_mail: str,
        password: str,
        server: str = "smtp.gmail.com",
        port: int = 465,
    ):
        self.server_addr = server
        self.server_port = port
        self.from_mail = from_mail
        self.password = password

    def send(self, subject: str, body: str, to_email: str) -> bool:
        """
        Envoie un email avec le sujet et le corps spécifiés à l'adresse e-mail donnée.

        Args:
            subject (str): Sujet de l'email.
            body (str): Corps de l'email.
            to_email (str): Adresse e-mail du destinataire.

        Returns:
            bool: True si l'email a été envoyé avec succès, False sinon.
        """

        if body.strip().startswith("<html>"):
            msg = MIMEText(body, "html")
        else:
            msg = MIMEText(body, "plain")
        msg["From"] = self.from_mail
        msg["To"] = to_email
        msg["Subject"] = subject

        try:
            server = smtplib.SMTP_SSL(self.server_addr, self.server_port, timeout=10)
            server.ehlo()
            server.login(self.from_mail, self.password)
            server.sendmail(self.from_mail, [to_email], msg.as_string())
            print(f"Mail envoyé à {to_email} avec succès.")
            server.quit()
            return True
        except smtplib.SMTPAuthenticationError as auth:
            print(f"Erreur d'authentification : blocage par Google : {auth}")
            return False
        except Exception as e:
            print(f"Erreur envoi mail vers {to_email}: {e}")
            return False

    def body_template(self, row) -> str :
        """
        Génère le corps HTML d'un email à partir d'une ligne de données.

        Args:
            row (Series): Une ligne de données contenant les informations nécessaires.

        Returns:
            str: Le corps HTML formaté de l'email.
        """
        anssi_id = row.get('ID ANSSI', '')
        date = row.get('Date', '')
        cve = row.get('CVE', 'Non disponible')
        cvss = row.get('CVSS', 'Non disponible')
        lien = row.get('Lien', '')
        title = row.get('Titre ANSSI', '')
        desc = row.get('Description', 'Aucune description disponible.')

        html = f"""
        <html>
            <head>
                <style>
                    .container {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: auto; border: 1px solid #ddd; border-radius: 8px; overflow: hidden; }}
                    .header {{ background-color: #d9534f; color: white; padding: 20px; text-align: center; }}
                    .content {{ padding: 20px; }}
                    .field {{ margin-bottom: 10px; }}
                    .label {{ font-weight: bold; color: #555; }}
                    .description {{ background-color: #f9f9f9; padding: 15px; border-left: 4px solid #d9534f; margin-top: 20px; font-style: italic; }}
                    .footer {{ text-align: center; padding: 15px; font-size: 0.8em; color: #888; background-color: #eee; }}
                    .button {{ display: inline-block; padding: 10px 20px; margin-top: 15px; background-color: #d9534f; color: white; text-decoration: none; border-radius: 5px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h2 style="margin:0;">Alerte de Sécurité ANSSI</h2>
                    </div>
                    <div class="content">
                        <div class="field"><span class="label">ID ANSSI :</span> {anssi_id}</div>
                        <div class="field"><span class="label">Titre :</span> {title}</div>
                        <div class="field"><span class="label">Date :</span> {date}</div>
                        <div class="field"><span class="label">CVE :</span> {cve}</div>
                        <div class="field"><span class="label">Score CVSS :</span> <span style="color: #d9534f; font-weight: bold;">{cvss}</span></div>

                        <div class="description">
                            <span class="label">Description :</span><br>
                            {desc}
                        </div>

                        <div style="text-align: center;">
                            <a href="{lien}" class="button">Consulter l'avis complet</a>
                        </div>
                    </div>
                    <div class="footer">
                        Ce message est généré automatiquement par votre système de veille CERT-FR.
                    </div>
                </div>
            </body>
        </html>
        """
        return html