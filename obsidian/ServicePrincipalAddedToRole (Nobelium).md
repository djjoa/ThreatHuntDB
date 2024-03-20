---
id: ca7c93e0-49d3-44ff-b07e-ae117ba13c9a
name: ServicePrincipalAddedToRole [Nobelium]
description: |
  One of the indicators of compromise for the Nobelium (formerly Solorigate) campaign was that unexpected service principals have been added to privileged roles. This query looks for service principals that have been added to any role.
  See Understanding "Solorigate"'s Identity IOCs - for Identity Vendors and their customers..
  Reference - https://techcommunity.microsoft.com/t5/azure-active-directory-identity/understanding-quot-solorigate-quot-s-identity-iocs-for-identity/ba-p/2007610
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - CloudAppEvents
tactics:
  - Privilege escalation
tags:
  - Nobelium
query: "```kusto\nlet queryTime = 1d;\nCloudAppEvents\n| where Timestamp > ago(queryTime)\n| where Application == \"Office 365\"\n| where ActionType == \"Add member to role.\"\n| extend EntityType = RawEventData.Target[2].ID, RoleName = RawEventData.ModifiedProperties[1].NewValue, RoleId = RawEventData.ModifiedProperties[2].NewValue\n| where EntityType == \"ServicePrincipal\"\n| project Timestamp , ActionType, ServicePrincipalName = RawEventData.Target[3].ID, ServicePrincipalId = RawEventData.Target[1].ID, RoleName, RoleId, ActorId = AccountObjectId , ActorDisplayName = AccountDisplayName \n```"
---

