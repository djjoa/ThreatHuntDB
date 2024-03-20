---
id: 3a72ba65-00fa-4bbc-b246-be1ff3f73ce1
name: Alerts related to account
description: |
  'Any Alerts that fired related to a given account during the range of +6h and -3d'
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
query: "```kusto\n\nlet GetAllAlertsForUser = (suspiciousEventTime:datetime, v_User:string){\n//-3d and +6h as some alerts fire after accumulation of events\nlet v_StartTime = suspiciousEventTime-3d;\nlet v_EndTime = suspiciousEventTime+6h;\nSecurityAlert\n| where TimeGenerated between (v_StartTime .. v_EndTime)\n| extend Extprop = parse_json(Entities)\n| mv-expand Extprop\n| extend Extprop = parse_json(Extprop)\n| extend Account = Extprop['Name']\n| extend Domain = Extprop['UPNSuffix']\n| extend Account = iif(isnotempty(Domain) and Extprop['Type']==\"account\", tolower(strcat(Account, \"@\", Domain)), iif(Extprop['Type']==\"account\", tolower(Account), \"\"))\n| where Account contains v_User\n| extend Computer = iff(Extprop['Type']==\"host\", Extprop['HostName'], '')\n| extend IpAddress = iff(Extprop[\"Type\"] == \"ip\",Extprop['Address'], '') \n| project TimeGenerated, AlertName, Computer, Account, IpAddress, ExtendedProperties \n| extend timestamp = TimeGenerated, AccountCustomEntity = Account, HostCustomEntity = Computer, IPCustomEntity = IpAddress\n};\n// change datetime value and username value below\nGetAllAlertsForUser(datetime('2019-01-20T10:02:51.000'), toupper(\"<username>\"))\n```"
---

