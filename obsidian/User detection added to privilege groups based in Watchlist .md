---
id: 8c5bc38a-438d-48fb-ae3f-7f356d3e5ba9
name: User detection added to privilege groups based in Watchlist
description: |
  'Based on a Watchlist Detects when a user has been added to a privileged group/role. We can exclude from the wathclist the users for whom we do not want this alert to be triggered'
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - SigninLogs
tactics:
  - Reconnaissance
  - PrivilegeEscalation
relevantTechniques:
  - T1548
query: "```kusto\nlet PrivilegedUsers = (_GetWatchlist('Accounts') | project SearchKey);\nlet timeRange = 3d;\nlet lookBack = 7d;\nAuditLogs\n| where LoggedByService == 'Core Directory' or LoggedByService == 'PIM'\n| where ActivityDisplayName has_any (\"Add eligible member to role\", \"Add member to role\")\n| where Identity !in (PrivilegedUsers)\n| mv-expand TargetResources\n| extend modProps = parse_json(TargetResources).modifiedProperties\n| mv-expand bagexpansion=array modProps\n| evaluate bag_unpack(modProps)\n| extend displayName = column_ifexists(\"displayName\", \"NotAvailable\"), newValue = column_ifexists(\"newValue\", \"NotAvailable\")\n//if you want only extract hig privilege Rol display or WellKnowObject\n| where newValue contains \"UserAccountAdmins\" or newValue contains \"User Administrator\" or newValue contains \"ApplicationAdministrators\" or newValue contains \"BuiltInRole\"\n //| project TimeGenerated, displayName, newValue, OperationName, Category, Identity, LoggedByService, Location, ResourceGroup \n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: Identity
---

