# Cyber mission control — données préparées par GitHub Actions

Un workflow planifié (toutes les 30 min) récupère côté GitHub les flux RSS (CERT-FR, FrenchBreaches, Zataz…), le catalogue CISA KEV,
les nouveaux CVE (CVEProject/cvelistV5) et l'historique, puis publie 5 petits fichiers JSON sur la branche `data`.
Le dashboard (`index.html`) les lit sur `raw.githubusercontent.com`, sans proxy public.

## Mise en place (dépôt public)
1. Dans le dépôt, remplace le contenu de la branche `main` par ces fichiers : `.github/workflows/update.yml`, `scripts/build_data.py`, `index.html`, ce README.
2. **Settings > Actions > General > Workflow permissions** : « Read and write permissions ».
3. Onglet **Actions** > « Mise à jour des données » > **Run workflow**. Vérifie que la branche `data` apparaît avec 5 fichiers.
4. Ouvre `index.html` en local. Le bouton « Réseau » teste l'accès aux données ; l'URL de base se règle dans la même fenêtre
   (par défaut `https://raw.githubusercontent.com/Woualy/kev-dashboard/data/`).

## Fichiers produits par l'Action
`feeds.json` (flux RSS), `kev.json`, `cve.json` (nouveaux CVE + score EPSS), `history.json`, `status.json` (météo Cloud & SaaS), `ransom.json` (revendications FR), `meta.json`.

## Bon à savoir
- Les flux sont définis en haut de `scripts/build_data.py` (liste `FEEDS`, mêmes id que le dashboard). Le bouton « Flux » du dashboard ne sert plus qu'au mode direct de secours.
- Un flux qui échoue côté serveur garde son ancien contenu ; l'erreur apparaît dans `meta.json` et dans la fenêtre « Flux ».
- GitHub peut retarder ou suspendre les workflows planifiés (inactivité du dépôt, forte charge) : en cas d'arrêt, relance manuellement.
- La branche `data` est écrasée à chaque exécution (un seul commit) pour ne pas gonfler le dépôt.
