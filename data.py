import pandas as pd
import re
from typing import List, Dict, Any

from requester import Requester

class DataManager :

    CERTFRs: List[Any]
    CVEs : List[str]

    Data : pd.DataFrame

    def __init__(self, csv_file=None) -> None:
        self.CERTFRs = []
        self.CVEs = []
        try :
            if(csv_file is not None and isinstance(csv_file, str)):
                self.Data = pd.read_csv(csv_file)
            else :
                self.Data = pd.read_csv("data.csv")
        except :
            self.Data = pd.DataFrame()

    def Step(self, url:str):
        """
        Action to read data from url and set into db 
        """
        # Récupère tout les CERTFR depuis l'url donnée, list de "Dict" 
        self.GetAllCERTFR(url)

        new_lines = []
        for entry in self.CERTFRs :
            cves = self.GetAllCVE(entry)
            if not cves:
                new_lines.append({
                    "Titre ANSS" : entry.title
                })
            else :
                for cve in cves :
                    new_lines.append(self.CreateRow(entry, cve))
        if new_lines:
            df_new = pd.DataFrame(new_lines)
            self.Data = pd.concat([self.Data, df_new], ignore_index=True)
            # Nettoyage des doublons potentiels (par exemple sur l'ID et la CVE)
            #self.Data.drop_duplicates(subset=["certfr_id", "cve_id"], inplace=True)
         
    def GetAllCERTFR(self, url: str) -> List[Any]:
        self.CERTFRs = Requester(url).request()
        return self.CERTFRs

    def GetAllCVE(self, entry) -> List[str]:
        try :
            json = Requester.json_details(f"{entry.link}json/")
            names = [cve['name'] for cve in json["cves"]]
            self.CVEs.extend(names)
            return names
        except Exception as e :
            print(f"Une erreur est apparu : {e}")
            return []

    def CreateRow(self, certfr, cve) :
        id_data,type_data = self.extract_info(certfr.link) 
        return {
            "ID ANSSI":id_data,
            "Titre ANSSI":certfr.title,
            "Type":type_data,
            "Date":certfr.published,
            "CVE": cve,
            "CVSS":None,
            "Base Severity":None,
            "CWE":None,
            "EPSS":None,
            "Lien":certfr.link,
            "Description":certfr.description,
        }

    def extract_info(self, link: str):
    # Regex : on cherche ce qui est entre les deux derniers slashs
    # (\w+) capture le type (avis ou alerte)
    # (CERTFR-\d{4}-\w+-\d+) capture l'identifiant complet
        pattern = r"https://www.cert.ssi.gouv.fr/(\w+)/(CERTFR-\d{4}-\w+-\d+)/"
        
        match = re.search(pattern, link)
        
        if match:
            data_type = match.group(1) # 'avis' ou 'alerte'
            certfr_id = match.group(2) # 'CERTFR-2025-AVI-1118'
            return certfr_id, data_type
        
        return None, None

    def GetDataFrame(self) -> pd.DataFrame:
        return self.Data