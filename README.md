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

## Wallboard (écran de l'open space)
`wallboard.html` : un seul écran très graphique (vigilance, CVE, failles exploitées, cloud, rançongiciels, fuites) avec un bandeau « URGENT / IMPORTANT / ACTUALITÉ » en bas, à partir des mêmes données.
Paramètres d'URL : `?t=9` (secondes par titre du bandeau), `?base=https://…/data/` (autre source de données).
Touches : flèches (titre précédent / suivant), F (plein écran). La page se recharge seule toutes les 6 heures.

## Entités surveillées (page Veille uniquement)
Bouton « Entités » : nom de l'organisation, domaines, fournisseurs. Les fuites, revendications de rançongiciels et dépêches qui les mentionnent apparaissent dans un bandeau rouge. La liste reste dans le navigateur (jamais dans le dépôt) ; elle est incluse dans l'export de configuration, qu'il ne faut donc pas publier.

## Mises à jour régulières
Les exécutions planifiées de GitHub (cron) sont « au mieux » : elles peuvent n'avoir lieu que toutes les quelques heures. Pour une cadence fiable, `trigger-update.ps1` déclenche le workflow toutes les 30 minutes depuis un poste ou serveur Windows toujours allumé (Planificateur de tâches). Le workflow se lance aussi à chaque modification de `scripts/` ou du workflow.

## Bon à savoir
- Les flux sont définis en haut de `scripts/build_data.py` (liste `FEEDS`, mêmes id que le dashboard). Le bouton « Flux » du dashboard ne sert plus qu'au mode direct de secours.
- Un flux qui échoue côté serveur garde son ancien contenu ; l'erreur apparaît dans `meta.json` et dans la fenêtre « Flux ».
- GitHub peut retarder ou suspendre les workflows planifiés (inactivité du dépôt, forte charge) : en cas d'arrêt, relance manuellement.
- La branche `data` est écrasée à chaque exécution (un seul commit) pour ne pas gonfler le dépôt.
