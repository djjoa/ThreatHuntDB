---
id: 84026aa0-7020-45d0-9f85-d526e43de2ab
name: Exchange Servers and Associated Security Alerts
description: |
  'This query will dynamically identify Exchange servers using common web paths used by the application in the csUriStem. The query
  will then collect MDE alerts from the SecurityAlert table using the identified Exchange Server hostnames.'
requiredDataConnectors:
  - connectorId: AzureMonitor(IIS)
    dataTypes:
      - W3CIISLog
  - connectorId: MicrosoftDefenderAdvancedThreatProtection
    dataTypes:
      - SecurityAlert (MDATP)
tactics:
  - InitialAccess
relevantTechniques:
  - T1190
tags:
  - Exchange
query: |-
  ```kusto

  W3CIISLog
  | where csUriStem has_any("/owa/auth/", "/ecp/healthcheck.htm", "/ews/exchange.asmx")
  | summarize by computer=tolower(Computer)
  | join kind=leftouter (
    SecurityAlert
    | extend alertData = parse_json(Entities)
    | mvexpand alertData
    | where alertData.Type == "host"
    | extend computer = iff(isnotempty(alertData.DnsDomain), tolower(strcat(tostring(alertData.HostName), "." , tostring(alertData.DnsDomain))),tolower(tostring(alertData.HostName)))
    | summarize Alerts=dcount(SystemAlertId), AlertTimes=make_list(TimeGenerated), AlertNames=make_list(AlertName) by computer
  ) on computer
  | project ExchangeServer=computer, Alerts, AlertTimes, AlertNames
  ```
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: ExchangeServer
---

