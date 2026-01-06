import pandas as pd
import re
from typing import List, Dict, Any
import time
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
    
    def EnrichAllCVE(self):
        """
        Parcourt le DataFrame et enrichit chaque ligne avec les données API.
        """
        print(f"Début de l'enrichissement pour {len(self.Data)} lignes...")
        self.Data['Base Severity'] = self.Data['Base Severity'].astype(object)
        self.Data['CWE'] = self.Data['CWE'].astype(object)
        self.Data['EPSS'] = self.Data['EPSS'].astype(object)
        for index, row in self.Data.iterrows():
            cve_id = row['CVE']
            if pd.isna(cve_id) or cve_id == "Non disponible":
                continue

            print(f"Enrichissement de {cve_id}...")
            
            # 1. Récupération des données MITRE (CVSS et CWE)
            mitre_data = self.get_mitre_data(cve_id)
            
            # 2. Récupération des données EPSS (Probabilité d'exploitation)
            epss_score = self.get_epss_data(cve_id)

            # Mise à jour du DataFrame
            self.Data.at[index, 'CVSS'] = mitre_data.get('cvss')
            self.Data.at[index, 'Base Severity'] = self.get_severity_label(mitre_data.get('cvss'))
            self.Data.at[index, 'CWE'] = mitre_data.get('cwe')
            self.Data.at[index, 'EPSS'] = epss_score
            if mitre_data.get('description'):
                self.Data.at[index, 'Description'] = mitre_data.get('description')

            #Rate Limiting 
            time.sleep(2) 

        # resumé des données enrichies 
        #print(self.Data[['CVE', 'Base Severity', 'CWE', 'EPSS']].head())
        #print(self.Data.describe())
        #print(self.Data['Base Severity'].value_counts())

    def get_mitre_data(self, cve_id: str) -> Dict[str, Any]:
        """Récupère CVSS, CWE et Description depuis l'API MITRE."""
        url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
        data = Requester.json_details(url)
        res = {'cvss': None, 'cwe': 'Non disponible', 'description': None}
        
        try:
            if not data or "containers" not in data:
                return res

            cna = data["containers"]["cna"]
            
            # Extraction de la description
            if "descriptions" in cna:
                res['description'] = cna["descriptions"][0].get("value")

            # Extraction du score CVSS (gestion des versions 3.1, 3.0 et 2.0)
            metrics = cna.get("metrics", [])
            for metric in metrics:
                for key in ["cvssV3_1", "cvssV3_0", "cvssV2_0"]:
                    if key in metric:
                        res['cvss'] = metric[key].get("baseScore")
                        break
                if res['cvss']: break

            # Extraction du CWE
            problem_types = cna.get("problemTypes", [])
            if problem_types and "descriptions" in problem_types[0]:
                res['cwe'] = problem_types[0]["descriptions"][0].get("cweId", "Non disponible")
                
        except Exception as e:
            print(f"Erreur MITRE pour {cve_id}: {e}")
        
        return res

    def get_epss_data(self, cve_id: str) -> Any:
        """Récupère le score EPSS depuis l'API FIRST."""
        url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
        data = Requester.json_details(url)
        try:
            epss_list = data.get("data", [])
            if epss_list:
                return epss_list[0].get("epss")
        except Exception as e:
            print(f"Erreur EPSS pour {cve_id}: {e}")
        return None

    def get_severity_label(self, score):
        """Détermine la sévérité en fonction du score CVSS."""
        if score is None: return "Inconnu"
        score = float(score)
        if score >= 9.0: return "Critical"
        if score >= 7.0: return "High"
        if score >= 4.0: return "Medium"
        return "Low"

    def GetDataFrame(self) -> pd.DataFrame:
        return self.Data