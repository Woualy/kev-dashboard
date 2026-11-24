<#
.SYNOPSIS
  Déclenche l'Action GitHub « Mise à jour des données » (workflow_dispatch), à lancer toutes les 30 minutes
  par le Planificateur de tâches Windows. Les exécutions planifiées de GitHub (cron) sont « au mieux » et
  peuvent n'avoir lieu que toutes les quelques heures ; un déclenchement externe est régulier.

.PREREQUIS (une seule fois, avec le compte qui exécutera la tâche)
  1. GitHub > Settings > Developer settings > Fine-grained personal access tokens :
     - dépôt : Woualy/kev-dashboard uniquement ; permission « Actions : Read and write » ; expiration 1 an.
  2. Enregistrer le jeton, chiffré pour ce compte Windows :
       New-Item -ItemType Directory -Force "$env:ProgramData\mission-control" | Out-Null
       Get-Credential -UserName token -Message "Collez le jeton GitHub comme mot de passe" |
         Export-Clixml "$env:ProgramData\mission-control\gh-token.xml"
  3. Planifier :
       schtasks /Create /SC MINUTE /MO 30 /TN "MissionControl-Update" /RU "<compte>" /RP * `
         /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\chemin\trigger-update.ps1"
#>
param(
  [string]$Repo      = 'Woualy/kev-dashboard',
  [string]$Workflow  = 'update.yml',
  [string]$Ref       = 'main',
  [string]$TokenFile = "$env:ProgramData\mission-control\gh-token.xml"
)
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try {
  $token = (Import-Clixml -Path $TokenFile).GetNetworkCredential().Password
  $headers = @{
    Authorization          = "Bearer $token"
    Accept                 = 'application/vnd.github+json'
    'X-GitHub-Api-Version' = '2022-11-28'
    'User-Agent'           = 'mission-control-trigger'
  }
  $uri  = "https://api.github.com/repos/$Repo/actions/workflows/$Workflow/dispatches"
  $body = @{ ref = $Ref } | ConvertTo-Json
  # derrière un proxy authentifié : le proxy système et les identifiants de la session sont utilisés
  Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $body -ContentType 'application/json' -ProxyUseDefaultCredentials | Out-Null
  Write-Output ("{0} OK : exécution demandée pour {1}" -f (Get-Date -Format s), $Repo)
} catch {
  Write-Output ("{0} ERREUR : {1}" -f (Get-Date -Format s), $_.Exception.Message)
  exit 1
}
