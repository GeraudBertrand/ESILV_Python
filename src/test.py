import os

import pandas as pd

from datetime import datetime
from dotenv import load_dotenv
from pathlib import Path

from mail import Mail
from data import DataManager

from main import NotifyUsersForCriticalVulnerability

def SendTestMail():
    """
    Méthode pour tester l'envoi d'un e-mail vers l'adresse de l'envoyeur.
    """
    load_dotenv()

    sender = os.getenv("MAIL_USER")
    password = os.getenv("MAIL_PWD")
    mail = Mail(from_mail=sender, password=password)
    test_recipient = sender
    subject = "Email Test"
    body = f"Ceci est un e-mail de test. \n Date actuelle : {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}"
    success = mail.send(subject, body, test_recipient)
    assert success, "Erreur : L'e-mail de test n'a pas pu être envoyé."

def ReadTestData():
    """
    Méthode pour tester la lecture des données via DataManager.
    """
    manager = DataManager()

    assert manager.Data is not None, "Le système n'a pas réussi à récupérer les données"
    assert not manager.Data.empty, "Le système a récupéré des données vides."
    print("Données récupérés avec ", len(manager.Data), " lignes.")
    print(manager.Data.head())

def SendTestMailFromDataCSV(target_id:str):
    """
    Méthode pour tester l'envoi d'un mail selon la lecture d'une ligne du dataframe de data.csv
    Utilise la méthode NotifyUsersForCriticalVulnerability de main.py pour tenter l'opération
    """
    load_dotenv()
    sender = os.getenv("MAIL_USER")
    password = os.getenv("MAIL_PWD")

    mail = Mail(from_mail=sender, password=password)
    manager = DataManager()

    result = manager.Data.loc[manager.Data["ID ANSSI"] == target_id]

    assert not result.empty, f"Aucune ligne trouvé pour cet id : {target_id}"

    users_path = Path(__file__).resolve().parent.parent / "users.csv"
    if not users_path.exists():
        users_path = Path.cwd() / "users.csv"

    users = pd.read_csv(users_path, sep=',').to_dict(orient='records')

    NotifyUsersForCriticalVulnerability(mail, users, result)




if __name__ == "__main__":
    """
    Zone de test pour les fonctionnalités d'envoi d'e-mail et de gestion des données.
    Fichier à n'utiliser que pour vérifier si les modules fonctionnent correctement.
    """
    print("Test zone")

    env_path = Path(__file__).resolve().parent.parent / ".env"

    load_dotenv(env_path)

    print("Sending test email...")
    SendTestMail()

    print("\nReading test data...")
    ReadTestData()

    print("\nSending test email from data CSV...")
    test_id = "CERTFR-2026-ALE-test"
    SendTestMailFromDataCSV(test_id)