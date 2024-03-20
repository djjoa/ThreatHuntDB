---
id: 8eff7055-9138-4edc-b8f0-48ea27e23c3c
name: Azure Key Vault Access Policy Manipulation
description: |
  'This query identifies instances where a user is added and subsequently removed from an Azure Key Vault access policy within a short duration, which could indicate attempts to credential access and persistence.'
requiredDataConnectors:
  - connectorId: AzureKeyVault
    dataTypes:
      - AzureDiagnostics
tactics:
  - CredentialAccess
relevantTechniques:
  - T1555
query: "```kusto\nlet timeframe = 10m;\nAzureDiagnostics\n| where ResourceType =~ \"VAULTS\"\n| where OperationName =~ \"VaultPatch\"\n| where ResultType =~ \"Success\"\n| extend UserObjectAdded = column_ifexists(\"addedAccessPolicy_ObjectId_g\",\"\")\n| extend AddedActor = identity_claim_http_schemas_xmlsoap_org_ws_2005_05_identity_claims_name_s\n| extend KeyAccessAdded = tostring(column_ifexists(\"addedAccessPolicy_Permissions_keys_s\",\"\"))\n| extend SecretAccessAdded = tostring(column_ifexists(\"addedAccessPolicy_Permissions_secrets_s\",\"\"))\n| extend CertAccessAdded = tostring(column_ifexists(\"addedAccessPolicy_Permissions_certificates_s\",\"\"))\n| where isnotempty(UserObjectAdded)\n| project AccessAddedTime=TimeGenerated, ResourceType, OperationName, ResultType, KeyVaultName=id_s, AddedActor, UserObjectAdded, KeyAccessAdded, SecretAccessAdded, CertAccessAdded\n| join kind=inner \n( \nAzureDiagnostics\n| where ResourceType =~ \"VAULTS\"\n| where OperationName =~ \"VaultPatch\"\n| where ResultType =~ \"Success\"\n| extend RemovedActor = identity_claim_http_schemas_xmlsoap_org_ws_2005_05_identity_claims_name_s\n| extend UserObjectRemoved = column_ifexists(\"removedAccessPolicy_ObjectId_g\", \"\")\n| extend KeyAccessRemoved = tostring(column_ifexists(\"removedAccessPolicy_Permissions_keys_s\",\"\"))\n| extend SecretAccessRemoved = tostring(column_ifexists(\"removedAccessPolicy_Permissions_secrets_s\",\"\"))\n| extend CertAccessRemoved = tostring(column_ifexists(\"removedAccessPolicy_Permissions_certificates_s\",\"\"))\n| where isnotempty(UserObjectRemoved)\n| project AccessRemovedTime=TimeGenerated, ResourceType, OperationName, ResultType, KeyVaultName=id_s, RemovedActor, UserObjectRemoved, KeyAccessRemoved, SecretAccessRemoved, CertAccessRemoved\n)\non KeyVaultName\n| extend TimeDelta = abs(AccessAddedTime - AccessRemovedTime)\n| where TimeDelta < timeframe\n| project KeyVaultName, AccessAddedTime, AddedActor, UserObjectAdded, KeyAccessAdded, SecretAccessAdded, CertAccessAdded, AccessRemovedTime, RemovedActor, UserObjectRemoved, KeyAccessRemoved, SecretAccessRemoved, CertAccessRemoved, TimeDelta\n| extend Account_0_AadUserId = UserObjectAdded\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: AadUserId
        columnName: UserObjectAdded
version: 1.0.1
---

