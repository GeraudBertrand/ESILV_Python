import os
import time

from dotenv import load_dotenv
from pathlib import Path

from mail import Mail
from data import DataManager

def SendTestMail():
    """Function to send a test email to verify mail sending functionality."""
    load_dotenv()

    sender = os.getenv("MAIL_USER")
    password = os.getenv("MAIL_PWD")
    mail = Mail(from_mail=sender, password=password)
    test_recipient = sender  # Sending test email to self
    subject = "Test Email"
    body = f"This is a test email to verify the mail sending functionality. \n Actual date : {time.time()}"
    success = mail.send(subject, body, test_recipient)
    assert success, "Failed to send test email."

def ReadTestData():
    """Function to read test data using DataManager."""
    manager = DataManager()

    assert manager.Data is not None, "Failed to fetch data."
    assert not manager.Data.empty, "Fetched data is empty."
    print("Data fetched successfully with", len(manager.Data), "entries.")
    print(manager.Data.head())


if __name__ == "__main__":
    print("Test zone")

    env_path = Path(__file__).resolve().parent.parent / ".env"

    load_dotenv(env_path)

    print("Sending test email...")
    SendTestMail()

    print("\nReading test data...")
    ReadTestData()