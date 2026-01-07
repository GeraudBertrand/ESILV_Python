import feedparser
from feedparser import FeedParserDict
from typing import List, Dict, Any

import requests


class Requester : 
  URL : str
  query : FeedParserDict
  entries : list

  def __init__(self, url: str) :
      self.URL = url
      self.entries = []

  def request(self, url = None) -> List[Any]:
    """ 
    Récupère toutes les données de l'url données et retourne un tableau de lien

    Args:
      url (string, optional): URL possible pour une requête différente. Defaults to None.

    Returns:
      List[FeedParserDict]: Listes d'entrées dans le corps de la réponse à l'url donnée
    """

    try :
      if(url is not None and isinstance(url, str)):
          self.URL = url
      query = feedparser.parse(self.URL)
      if(query.bozo) :
          raise Exception("Format de flux incorrecte")
      self.entries = query.entries
      print(f"Requête réussie : {len(self.entries)} entrées trouvées.")
      return self.entries
    except Exception as e:
        print(f"Erreur de requête sur {self.URL} : {e}")
        return []


  @staticmethod
  def json_details( url: str) -> Dict[str, Any]:
    try :
      session = requests.Session()
      response = session.get(url)
      response.raise_for_status()
      return response.json()
    except Exception as e :
      print(f"Erreur lors de la récupération du JSON {url}: {e}") 
      return {}