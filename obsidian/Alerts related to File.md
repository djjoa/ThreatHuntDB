---
id: 11d808a1-32fe-4618-946a-cfd43523347a
name: Alerts related to File
description: |
  'Any Alerts that fired related to a given File during the range of +6h and -3d'
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
query: "```kusto\n\nlet GetAllAlertsWithFile = (suspiciousEventTime:datetime, v_File:string){\nlet v_StartTime = suspiciousEventTime-1d;\nlet v_EndTime = suspiciousEventTime+1d;\nSecurityAlert\n| where TimeGenerated between (v_StartTime .. v_EndTime)\n| where ExtendedProperties has v_File\n    // expand JSON properties\n| extend Extprop = parse_json(ExtendedProperties)\n| extend Computer = iff(isnotempty(toupper(tostring(Extprop[\"Compromised Host\"]))), toupper(tostring(Extprop[\"Compromised Host\"])), tostring(parse_json(Entities)[0].HostName))\n| extend Account = iff(isnotempty(tolower(tostring(Extprop[\"User Name\"]))), tolower(tostring(Extprop[\"User Name\"])), tolower(tostring(Extprop[\"user name\"])))\n| extend IpAddress = tostring(parse_json(ExtendedProperties).[\"Client Address\"]) \n| extend timestamp = TimeGenerated, AccountCustomEntity = Account, HostCustomEntity = Computer, IPCustomEntity = IpAddress\n};\n// change datetime value and <filename> value below\nGetAllAlertsWithFile(datetime('2019-01-18T10:36:07Z'), \"<filename>\")\n```"
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

