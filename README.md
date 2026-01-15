# ANSSI Moniteur d'alerte & CVE Analyseur de risque

Projet  Python A3 - ESILV

## Objectif

Ce projet est un système de veille automatisé qui surveille les avis et alertes du **CERT-FR (ANSSI)**. Il enrichit les données brutes avec des informations critiques (CVSS, CWE, EPSS) provenant d'API internationales pour permettre une analyse de risque précise et l'envoi de notifications ciblées.

## Fonctionnalités

* **Surveillance active** : Scan périodique des flux RSS de l'ANSSI (Alertes et Avis).
* **Enrichissement de données** : Récupération automatique des détails via les API du MITRE et de FIRST.org (CVSS, CWE et score de probabilité d'exploitation EPSS).
* **Alerting intelligent** : Envoi de mails HTML formatés aux administrateurs dès qu'une vulnérabilité critique concerne un logiciel de leur parc.
* **Analyse visuelle** : Notebook Jupyter complet pour l'étude statistique des menaces (tendances temporelles, corrélations gravité/exploitation, profils éditeurs).

## Installation

1. Installez les dépendances nécessaires :

   ```bash
   pip install -r requirements.txt


## Configuration (users.csv)

Configurez vos alertes dans le fichier users.csv à la racine du projet. Le système envoie une notification uniquement si la sévérité est Critical et que le nom du logiciel apparaît dans l'alerte.

Exemple de contenu pour users.csv :

Extrait de code

mail,logiciels
<votre_email@gmail.com>,"[""Fortinet"", ""Microsoft"", ""Ivanti"", ""Cisco""]"

## Utilisation

Lancer le moniteur (Boucle de surveillance et notifications par mail) :

Bash

python src/main.py
Note : Le script vérifie les flux toutes les 10 minutes et respecte les quotas des API (rate limiting).

Lancer les visualisations : Ouvrez et exécutez le notebook src/visualisation.ipynb ou visualidation.html pour générer les graphiques d'analyse de la base de données data.csv.

## Structure du Projet

src/main.py : Script principal gérant la boucle de surveillance et la logique de notification.

src/data.py : Gestionnaire de données (traitement, déduplication et enrichissement via API).

src/requester.py : Module technique pour les requêtes HTTP et le parsing des flux RSS.

src/mail.py : Classe gérant l'envoi des emails via SMTP et le template HTML.

data.csv : Base de données locale (Semicolon separated) stockant l'historique enrichi.

users.csv : Configuration des utilisateurs et des logiciels à surveiller.
