# Exemples de requêtes KQL pour le Hunting dans Microsoft Defender

Recherche des connexions RDP suspectes 
Objectif : Identifier les connexions RDP répétées provenant d’adresses IP externes.

DeviceNetworkEvents
| where RemotePort == 3389
| summarize count() by DeviceName, RemoteIP
| where count_ > 10

—

Détection des processus anormaux exécutés
Objectif : Identifier les utilisations inhabituelles de PowerShell.

DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine contains « powershell.exe »
| summarize count() by DeviceName, ProcessCommandLine
| order by count_ desc

—

Recherche de comportements liés au pass-the-hash
Objectif : Repérer des mouvements latéraux utilisant des comptes d’ordinateurs compromis.

SecurityEvent
| where EventID == 4624 and LogonType == 3
| where AccountName endswith « $ »
| summarize count() by AccountName, IpAddress
| where count_ > 5

—

Analyse des échecs de connexions
Objectif : Identifier les tentatives de connexions répétées qui ont échoué.

SigninLogs
| where ResultType == « 50126 »
| summarize FailedAttempts = count() by UserPrincipalName, Location
| where FailedAttempts > 10

—

Recherche de transferts de fichiers anormaux
Objectif : Surveiller les fichiers téléchargés ou déplacés dans des emplacements inhabituels.

DeviceFileEvents
| where ActionType == « FileCreated »
| where FolderPath contains « C:\\Temp »
| summarize count() by FileName, DeviceName

—

Inspection des connexions à des domaines malveillants
Objectif : Détecter les connexions à des sites suspects listés comme malveillants.

DeviceNetworkEvents
| join Kind=inner ThreatIntelligenceIndicator on $left.RemoteUrl == $right.Url
| where ThreatType == « Malware »
| summarize by DeviceName, RemoteUrl, TimeGenerated

—

Analyse des accès administratifs
Objectif : Suivre les connexions administratives pour détecter d’éventuelles anomalies.

DeviceLogonEvents
| where AccountType == « Admin »
| summarize count() by AccountName, LogonTime = bin(TimeGenerated, 1h)
| order by LogonTime desc

—

Recherche des scripts exécutés depuis des emplacements temporaires
Objectif : Identifier l’exécution de scripts à partir de dossiers temporaires.

DeviceProcessEvents
| where ProcessCommandLine contains « .ps1 » and FolderPath contains « C:\\Temp »
| summarize count() by DeviceName, ProcessCommandLine

—

Détection des modifications de privilèges
Objectif : Surveiller les modifications des niveaux d’accès des comptes.

SecurityEvent
| where EventID == 4670
| summarize count() by TargetAccount, InitiatingProcess

—

Analyse des journaux de partage réseau
Objectif : Identifier une utilisation suspecte des partages SMB.

DeviceNetworkEvents
| where LocalPort == 445
| summarize count() by DeviceName, RemoteIP
| where count_ > 20

—

Recherches des activités inhabituelles des utilisateurs
Objectif : Identifier des ajouts suspects à des rôles sensibles.

AuditLogs
| where OperationName contains « Add member to role »
| summarize count() by InitiatedBy, Role, TimeGenerated

—

Détection des exécutions de binaires spécifiques
Objectif : Identifier des outils malveillants ou d’investigation potentiellement utilisés.

DeviceProcessEvents
| where FileName in (« mimikatz.exe », « procmon.exe »)
| summarize count() by FileName, DeviceName, UserName