from data import DataManager

URL_ALERTE = "https://cert.ssi.gouv.fr/alerte/feed/"
URL_AVIS = "https://cert.ssi.gouv.fr/avis/feed/"


if __name__ == "__main__":
    manager = DataManager()
    manager.Step(URL_ALERTE)
    manager.EnrichAllCVE()
    
