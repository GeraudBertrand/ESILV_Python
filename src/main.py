import time
from data import DataManager
from mail import Mail
from typing import Any
import pandas as pd

URL_ALERTE = "https://cert.ssi.gouv.fr/alerte/feed/"
URL_AVIS = "https://cert.ssi.gouv.fr/avis/feed/"



def Step(manager: DataManager, url:str) -> list[dict[str, Any]] :
    manager.GetAllCERTFR(url)
    lines = manager.InsertNewData()
    if(lines):
        df_new = manager.TransformToDataFrame(lines)
        manager.EnrichAllCVE(df_new)

        manager.InsertRow(df_new)
        return lines
    return []


def NotifyUsersForCriticalVulnerability(mail: Mail, users: list[dict[str, Any]], df: pd.DataFrame) -> None:
        """Analyse les lignes et envoie un mail aux utilisateurs dont les logiciels
        sont mentionnés dans le titre ou la description quand la vulnérabilité est critique.
        """
        if df is None or df.empty:
            return

        for index, row in df.iterrows():
            try:
                severity = row.get('Base Severity') if 'Base Severity' in row else None
                cvss = row.get('CVSS') if 'CVSS' in row else None
                is_critical = (severity == 'Critical') or (cvss is not None and pd.notna(cvss) and float(cvss) >= 9.0)
            except Exception:
                is_critical = False

            if not is_critical:
                continue

            product = str(row.get('Produit', ''))
            title = str(row.get('Titre ANSSI', ''))
            desc = str(row.get('Description', '')) if row.get('Description') is not None else ''

            for user in users:
                user_mail = user.get('mail') or user.get('email')
                if not user_mail:
                    continue
                logiciels = user.get('logiciels', []) or []

                for logi in logiciels:
                    if not logi:
                        continue
                    s = str(logi).lower()
                    if s in product.lower():
                        subject = f"[ALERTE CRITIQUE] {row.get('ID ANSSI', '')} - {title}"
                        body = (
                            f"ID: {row.get('ID ANSSI','')}\n"
                            f"Titre: {title}\n"
                            f"Date: {row.get('Date','')}\n"
                            f"CVE: {row.get('CVE','Non disponible')}\n"
                            f"CVSS: {row.get('CVSS','Non disponible')}\n"
                            f"Lien: {row.get('Lien','')}\n\n"
                            f"Description:\n{desc}"
                        )
                        try:
                            mail.send(subject, body, user_mail)
                        except Exception as e:
                            print(f"Erreur envoi notification vers {user_mail}: {e}")
                        break


if __name__ == "__main__":

    users = pd.read_csv("../users.csv", sep=',').to_dict(orient='records')

    mailSender = Mail("esilv4473@gmail.com", "Es1lv@2026")
    manager = DataManager()
    Step(manager, URL_AVIS)


    while True :
        data = Step(manager, URL_ALERTE)
        if(data):
            try:
                NotifyUsersForCriticalVulnerability(mailSender, users, data)
            except Exception as e:
                print(f"Erreur lors de la notification des utilisateurs: {e}")

        time.sleep(3600)