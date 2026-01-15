import time
from data import DataManager
from mail import Mail
from typing import Any
from pathlib import Path
import pandas as pd
import os
from dotenv import load_dotenv


URL_ALERTE = "https://cert.ssi.gouv.fr/alerte/feed/"
URL_AVIS = "https://cert.ssi.gouv.fr/avis/feed/"

SLEEP_INTERNAL = 600
TIME_DISTANCE = 3600 * 24  # 24 heure en secondes


def Step(manager: DataManager, url:str) -> pd.DataFrame :
    """
    Exécute une étape de récupération, transformation, enrichissement et insertion des données.
    1. Récupère toutes les données du flux RSS.
    2. Transforme les données brutes en lignes exploitables.
    3. Transforme les nouvelles données en DataFrame.
    4. Enrichit les données CVE via des API externes.
    5. Insère les nouvelles lignes dans le csv.

    Args:
        manager (DataManager): Instance de DataManager pour gérer les données.
        url (str): URL du flux RSS à traiter.

    Returns:
        pd.DataFrame: DataFrame des nouvelles données insérées.
    """
    manager.GetAllCERTFR(url)
    lines = manager.InsertNewData()
    if(lines):
        df_new = manager.TransformToDataFrame(lines)
        manager.EnrichAllCVE(df_new)

        manager.InsertRow(df_new)
        return df_new
    return None


def NotifyUsersForCriticalVulnerability(mail: Mail, users: list[dict[str, Any]], df: pd.DataFrame) -> None:
        """Analyse les lignes et envoie un mail aux utilisateurs dont les logiciels
        sont mentionnés dans le titre ou la description quand la vulnérabilité est critique.

        Args:
            mail (Mail): Instance de Mail pour envoyer les emails.
            users (list[dict[str, Any]]): Liste des utilisateurs à notifier.
            df (pd.DataFrame): DataFrame des nouvelles données à analyser.
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
                is_less_than_1_hour = (time.time() - time.mktime(time.strptime(date, '%a, %d %b %Y %H:%M:%S %z'))) < TIME_DISTANCE

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
    load_dotenv()

    # locate users.csv relative to the project root (parent of src)
    users_path = Path(__file__).resolve().parent.parent / "users.csv"
    if not users_path.exists():
        # fallback to current working directory
        users_path = Path.cwd() / "users.csv"

    users = pd.read_csv(users_path, sep=',').to_dict(orient='records')

    sender = os.getenv("MAIL_USER")
    password =  os.getenv("MAIL_PWD")
    mailSender = Mail(from_mail= sender, password= password)
    manager = DataManager()
    Step(manager, URL_AVIS)

    print("\n# Surveillance du flux RSS activée...\n")

    while True :
        try :
            data = Step(manager, URL_ALERTE)
            if(data is not None and not data.empty):
                try:
                    # Remplacer data par test_mail pour tester les notifications sur une alerte spécifique
                    # test_mail = manager.Data[manager.Data['ID ANSSI'] == 'CERTFR-2026-ALE-test']
                    NotifyUsersForCriticalVulnerability(mailSender, users, data)           
                except Exception as e:
                    print(f"Erreur lors de la notification des utilisateurs: {e}")
            else :
                print("Aucune nouvelle donnée à vérifier.")
            print(f"\n# Sommeil pour {SLEEP_INTERNAL}s...")
            time.sleep(SLEEP_INTERNAL)
        except KeyboardInterrupt:
                print("Arrêt du moniteur...")
                break
        except Exception as e:
            print(f"Erreur lors de la surveillance : {e}")
            time.sleep(60)