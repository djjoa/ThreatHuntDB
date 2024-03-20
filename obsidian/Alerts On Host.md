---
id: 61a6edc0-e71a-4084-8f3c-05a58e1b9012
name: Alerts On Host
description: |
  'Any Alerts that fired on a given host during the range of +6h and -3d'
requiredDataConnectors:
  - connectorId: AzureSecurityCenter
    dataTypes:
      - SecurityAlert
  - connectorId: MicrosoftCloudAppSecurity
    dataTypes:
      - SecurityAlert
tactics:
  - Persistence
  - Discovery
  - LateralMovement
  - Collection
query: "```kusto\n\nlet GetAllAlertsOnHost = (suspiciousEventTime:datetime, v_Host:string){\n//-3d and +6h as some alerts fire after accumulation of events\nlet v_StartTime = suspiciousEventTime-3d;\nlet v_EndTime = suspiciousEventTime+6h;\nSecurityAlert\n| where TimeGenerated between (v_StartTime .. v_EndTime)\n// expand JSON properties\n| extend Extprop = parse_json(ExtendedProperties)\n| extend Computer = iff(isnotempty(toupper(tostring(Extprop[\"Compromised Host\"]))), toupper(tostring(Extprop[\"Compromised Host\"])), tostring(parse_json(Entities)[0].HostName))\n| where Computer contains v_Host\n| extend Account = iff(isnotempty(tolower(tostring(Extprop[\"User Name\"]))), tolower(tostring(Extprop[\"User Name\"])), tolower(tostring(Extprop[\"user name\"])))\n| extend IpAddress = tostring(parse_json(ExtendedProperties).[\"Client Address\"]) \n| project TimeGenerated, AlertName, Computer, Account, IpAddress, ExtendedProperties\n| extend timestamp = TimeGenerated, AccountCustomEntity = Account, HostCustomEntity = Computer, IPCustomEntity = IpAddress\n};\n// change datetime value and hostname value below\nGetAllAlertsOnHost(datetime('2019-01-20T10:02:51.000'), toupper(\"<hostname>\"))\n```"
version: 1.0.0
metadata:
  source:
    kind: Community
  author:
    name: Shain
  support:
    tier: Community
  categories:
    domains: ["Security - Other"]
---

