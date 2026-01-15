import os
import pandas as pd
import re
import time

from pathlib import Path
from typing import List, Dict, Any, Optional
from requester import Requester

class DataManager :
    """
    Gère les données de CERTFR et les opérations associées.

    Args:
        csv_path (Optional[str]): Chemin vers le fichier CSV pour stocker les données.

    Attributes:
        sleep_rate (int): Temps d'attente (en seconde) entre les requêtes pour éviter le rate limiting
        csv_file_path (str): Chemin vers le fichier CSV.
        CERTFRs (List[Any]): Liste des entrées CERTFR récupérées.
        CVEs (List[str]): Liste des CVE extraites.
        Data (pd.DataFrame): DataFrame contenant les données chargées depuis le CSV.
    """

    sleep_rate = 2  
    csv_file_path: str
    CERTFRs: List[Any]
    CVEs : List[str]

    Data : pd.DataFrame

    def __init__(self, csv_path=None) -> None:
        self.CERTFRs = []
        self.CVEs = []

        if csv_path is not None :
            self.csv_file_path = csv_path
        else :
            self.csv_file_path = Path(__file__).resolve().parent.parent / "data.csv"
            if not self.csv_file_path.exists():
                self.csv_file_path = Path.cwd() / "data.csv"
        try :
            # read using semicolon separator to match data.csv
            self.Data = pd.read_csv(self.csv_file_path, sep=';')
        except Exception as e :
            print(f"Erreur lecture fichier data.csv : {e}")
            self.Data = pd.DataFrame()

    def InsertNewData(self) -> list[dict[str, Any]] :
        """Insère les nouvelles données CERTFR et retourne les nouvelles lignes ajoutées."""
        new_lines = []
        for entry in self.CERTFRs :
            cves = self.GetAllCVE(entry)
            if not cves:
                new_lines.append(self.CreateRow(entry))
            else :
                for cve in cves :
                    new_lines.append(self.CreateRow(entry, cve))
        return new_lines

    def TransformToDataFrame(self, new_lines: list[dict[str, Any]]) -> pd.DataFrame :
        """Transforme les nouvelles lignes en DataFrame et filtre les doublons."""
        df_new = pd.DataFrame(new_lines)

        if not self.Data.empty and set(["ID ANSSI", "CVE"]).issubset(self.Data.columns):
            existing_pairs = set()
            for _, r in self.Data[["ID ANSSI", "CVE"]].dropna().iterrows():
                existing_pairs.add((r["ID ANSSI"], r["CVE"]))

            def is_new_row(r):
                return (r.get("ID ANSSI"), r.get("CVE")) not in existing_pairs

            df_to_append = df_new[df_new.apply(is_new_row, axis=1)]
        else:
            df_to_append = df_new
        return df_to_append


    def InsertRow(self, row) -> None :
        """
        Insère les nouvelles lignes dans le CSV et met à jour le DataFrame interne.

        Args :
            row (pd.DataFrame): Ligne à insérer.
        """
        if not row.empty:
                write_header = not os.path.exists(self.csv_file_path) or os.path.getsize(self.csv_file_path) == 0
                row.to_csv(self.csv_file_path, sep=';', index=False, mode='a', header=write_header)

                if self.Data.empty:
                    self.Data = row.reset_index(drop=True)
                else:
                    self.Data = pd.concat([self.Data, row], ignore_index=True)


    def GetAllCERTFR(self, url: str) -> List[Any]:
        """
        Récupère toutes les entrées CERTFR depuis le flux RSS.

        Args:
            url (str): URL du flux RSS CERTFR.
        """
        self.CERTFRs = Requester(url).request()
        return self.CERTFRs

    def GetAllCVE(self, entry) -> List[str]:
        """
        Récupère toutes les CVE associées à une entrée CERTFR.

        Args:
            entry: Entrée CERTFR à analyser.
        """
        try :
            json = Requester.json_details(f"{entry.link}json/")
            names = [cve['name'] for cve in json["cves"]]
            self.CVEs.extend(names)
            return names
        except Exception as e :
            print(f"Une erreur est apparu : {e}")
            return []

    def CreateRow(self, certfr, cve = None) -> dict[str, Any]:
        """
        Crée une ligne de données à partir d'une entrée CERTFR et d'une CVE optionnelle.

        Args:
            certfr: Entrée CERTFR.
            cve (Optional[str]): CVE associée.

        Returns:
            dict[str, Any]: Dictionnaire représentant la ligne de données.
        """
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
            "Description": self.sanitize_desc(certfr.description),
            "Éditeur" : [],
            "Produits" : [],
            "Versions" : []
        }

    def extract_info(self, link: str) -> tuple[Optional[str], Optional[str]]:
        """
        Extrait l'ID ANSSI et le type (avis ou alerte) depuis le lien CERTFR.

        Args:
            link (str): Lien CERTFR.

        Returns:
            tuple: (ID ANSSI, type)
        """
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
    
    def EnrichAllCVE(self, df: pd.DataFrame):
        """
        Parcourt le DataFrame et enrichit chaque ligne avec les données API.
        Utilise un rate limiting pour éviter de surcharger les API externes.

        Args:
            df (pd.DataFrame): DataFrame des nouvelles données à enrichir.
        """
        total_rows = len(df)
        if total_rows == 0:
            print("Aucune nouvelle ligne à enrichir.")
            return
        print(f"Début de l'enrichissement pour {total_rows} lignes...")

        df['Base Severity'] = df['Base Severity'].astype(object)
        df['CWE'] = df['CWE'].astype(object)
        df['EPSS'] = df['EPSS'].astype(object)
        df['Produits'] = df['Produits'].astype(object)
        df['Éditeur'] = df['Éditeur'].astype(object)
        df['Versions'] = df['Versions'].astype(object)
        for i, (index, row) in enumerate(df.iterrows()):
            progression = ((i + 1) / total_rows) * 100

            cve_id = row['CVE']
            if pd.isna(cve_id) or cve_id == "Non disponible":
                continue

            print(f"[{progression:.1f}%] Enrichissement de {cve_id}...")

            mitre_data = self.get_mitre_data(cve_id)
            epss_score = self.get_epss_data(cve_id)

            df.at[index, 'CVSS'] = mitre_data.get('cvss')
            df.at[index, 'Produits'] = mitre_data.get('product')
            df.at[index, 'Éditeur'] = mitre_data.get('vendor')
            df.at[index, 'Versions'] = mitre_data.get('version')
            df.at[index, 'Base Severity'] = self.get_severity_label(mitre_data.get('cvss'))
            df.at[index, 'CWE'] = mitre_data.get('cwe')
            df.at[index, 'EPSS'] = epss_score
            if mitre_data.get('description'):
                df.at[index, 'Description'] = self.sanitize_desc(mitre_data.get('description'))

            time.sleep(self.sleep_rate) 

        # resumé des données enrichies
        #print(df[['CVE', 'Base Severity', 'CWE', 'EPSS']].head())
        #print(df.describe())
        #print(df['Base Severity'].value_counts())

    def get_mitre_data(self, cve_id: str) -> Dict[str, Any]:
        """
        Récupère CVSS, CWE et Description depuis l'API MITRE.

        Args:
            cve_id (str): Identifiant CVE.

        Returns:
            dict[str, Any]: Dictionnaire contenant les données récupérées.
        """
        url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
        data = Requester.json_details(url)
        res = {'cvss': None, 'cwe': 'Non disponible', 'description': None, 'product': [], 'vendor': [], 'version': []}

        try:
            if not data or "containers" not in data:
                return res

            cna = data["containers"]["cna"]

            if "descriptions" in cna:
                res['description'] = cna["descriptions"][0].get("value")
            if 'affected' in cna :
                for prod in cna['affected'] :
                    prod_name = prod.get('product') or ''
                    vend_name = prod.get('vendor') or ''
                    if prod_name:
                        res['product'].append(prod_name)
                    if vend_name:
                        res['vendor'].append(vend_name)

                    versions = prod.get('versions', []) or []
                    for version in versions:
                        ver = version.get('lessThanOrEqual') or version.get('lessThan') or version.get('version')
                        if ver:
                            res['version'].append(ver)

            metrics = cna.get("metrics", [])
            for metric in metrics:
                for key in ["cvssV3_1", "cvssV3_0", "cvssV2_0"]:
                    if key in metric:
                        res['cvss'] = metric[key].get("baseScore")
                        break
                if res['cvss']: break

            problem_types = cna.get("problemTypes", [])
            if problem_types and "descriptions" in problem_types[0]:
                res['cwe'] = problem_types[0]["descriptions"][0].get("cweId", "Non disponible")

        except Exception as e:
            print(f"Erreur MITRE pour {cve_id}: {e}")

        return res

    def get_epss_data(self, cve_id: str) -> Optional[float]:
        """
        Récupère le score EPSS depuis l'API FIRST.

        Args:
            cve_id (str): Identifiant CVE.

        Returns:
            Any: Score EPSS ou None si non disponible.
        """
        url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
        data = Requester.json_details(url)
        try:
            epss_list = data.get("data", [])
            if epss_list:
                return epss_list[0].get("epss")
        except Exception as e:
            print(f"Erreur EPSS pour {cve_id}: {e}")
        return None

    def get_severity_label(self, score) -> str:
        """
        Détermine la sévérité en fonction du score CVSS.

        Args:
            score (Any): Score CVSS.

        Returns:
            str: Étiquette de sévérité.
        """
        if score is None: return "Inconnu"
        score = float(score)
        if score >= 9.0: return "Critical"
        if score >= 7.0: return "High"
        if score >= 4.0: return "Medium"
        return "Low"


    def sanitize_desc(self, text: str) -> str :
        """
        Nettoie une description en remplaçant les caractères de retour à la ligne par des espaces.

        Args:
            text (str): Texte à nettoyer.

        Returns:
            str: Texte nettoyé.
        """
        if( text is None) :
            return text
        try:
            s = str(text)
            s = s.replace('\r', ' ').replace('\n', ' ')
            s = re.sub(r"\s+", ' ', s).strip()
            return s
        except Exception:
            return text

    def GetDataFrame(self) -> pd.DataFrame:
        """
        Retourne le DataFrame interne contenant les données.

        Returns:
            pd.DataFrame: DataFrame des données.
        """
        return self.Data