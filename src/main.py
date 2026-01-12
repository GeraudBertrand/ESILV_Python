import time
from data import DataManager
from mail import Mail
from typing import Any
from pathlib import Path
import pandas as pd

URL_ALERTE = "https://cert.ssi.gouv.fr/alerte/feed/"
URL_AVIS = "https://cert.ssi.gouv.fr/avis/feed/"

SLEEP_INTERNAL = 600


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

        df.sort_values(by='Date', ascending=False, inplace=True)

        for index, row in df.iterrows():
            try:
                severity = row.get('Base Severity') if 'Base Severity' in row else None
                cvss = row.get('CVSS') if 'CVSS' in row else None
                is_critical = (severity == 'Critical') or (cvss is not None and pd.notna(cvss) and float(cvss) >= 9.0)
                date = row.get('Date', '')
                is_less_than_1_hour = (time.time() - time.mktime(time.strptime(date, '%a, %d %b %Y %H:%M:%S %z'))) < 3600

            except Exception:
                is_critical = False
                is_less_than_1_hour = False

            if not is_critical and not is_less_than_1_hour:
                continue

            product = str(row.get('Produit', ''))
            title = str(row.get('Titre ANSSI', ''))

            for user in users:
                user_mail = user.get('mail') or user.get('email')
                if not user_mail:
                    continue
                logiciels = user.get('logiciels', []) or []

                for logi in logiciels:
                    if not logi:
                        continue
                    s = str(logi).lower()
                    if s in product.lower() or s in title.lower():
                        subject = f"[ALERTE CRITIQUE] {row.get('ID ANSSI', '')} - {title}"
                        body =mail.body_template(row)
                        try:
                            mail.send(subject, body, user_mail)
                        except Exception as e:
                            print(f"Erreur envoi notification vers {user_mail}: {e}")
                        break


if __name__ == "__main__":

    # locate users.csv relative to the project root (parent of src)
    users_path = Path(__file__).resolve().parent.parent / "users.csv"
    if not users_path.exists():
        # fallback to current working directory
        users_path = Path.cwd() / "users.csv"

    users = pd.read_csv(users_path, sep=',').to_dict(orient='records')

    mailSender = Mail("esilv4473@gmail.com", "Es1lv@2026")
    manager = DataManager()
    Step(manager, URL_ALERTE)

    print("🚀 Surveillance du flux RSS activée...")

    # while True :
    #     try :
    #         data = Step(manager, URL_ALERTE)
    #         if(data):
    #             try:
    #                 NotifyUsersForCriticalVulnerability(mailSender, users, data)
    #             except Exception as e:
    #                 print(f"Erreur lors de la notification des utilisateurs: {e}")

    #         print(f"💤 Sommeil pour {CHECK_INTERVAL}s...")
    #         time.sleep(SLEEP_INTERNAL)
    #     except KeyboardInterrupt:
    #             print("Stopping monitor...")
    #             break
    #     except Exception as e:
    #         print(f"Erreur lors de la surveillance : {e}")
    #         time.sleep(60)