import os
import time

from dotenv import load_dotenv
from pathlib import Path

from mail import Mail
from data import DataManager

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
    body = f"Ceci est un e-mail de test. \n Date actuelle : {time.time()}"
    success = mail.send(subject, body, test_recipient)
    assert success, "Erreur : L'e-mail de test n'a pas pu être envoyé."

def ReadTestData():
    """
    Méthode pour tester la lecture des données via DataManager.
    """
    manager = DataManager()

    assert manager.Data is not None, "Failed to fetch data."
    assert not manager.Data.empty, "Fetched data is empty."
    print("Data fetched successfully with", len(manager.Data), "entries.")
    print(manager.Data.head())


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