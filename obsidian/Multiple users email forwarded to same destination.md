---
id: a1551ae4-f61c-4bca-9c57-4d0d681db2e9
name: Multiple users email forwarded to same destination
description: "'Identifies when multiple (more than one) users mailboxes are configured to forward to the same destination. \nThis could be an attacker-controlled destination mailbox configured to collect mail from multiple compromised user accounts.'\n"
severity: Medium
status: Available
requiredDataConnectors:
  - connectorId: Office365
    dataTypes:
      - OfficeActivity
queryFrequency: 1d
queryPeriod: 7d
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Collection
  - Exfiltration
relevantTechniques:
  - T1114
  - T1020
query: |-
  ```kusto
  let queryfrequency = 1d;
  let queryperiod = 7d;
  OfficeActivity
  | where TimeGenerated > ago(queryperiod)
  | where OfficeWorkload =~ "Exchange"
  //| where Operation in ("Set-Mailbox", "New-InboxRule", "Set-InboxRule")
  | where Parameters has_any ("ForwardTo", "RedirectTo", "ForwardingSmtpAddress")
  | mv-apply DynamicParameters = todynamic(Parameters) on (summarize ParsedParameters = make_bag(bag_pack(tostring(DynamicParameters.Name), DynamicParameters.Value)))
  | evaluate bag_unpack(ParsedParameters, columnsConflict='replace_source')
  | extend DestinationMailAddress = tolower(case(
      isnotempty(column_ifexists("ForwardTo", "")), column_ifexists("ForwardTo", ""),
      isnotempty(column_ifexists("RedirectTo", "")), column_ifexists("RedirectTo", ""),
      isnotempty(column_ifexists("ForwardingSmtpAddress", "")), trim_start(@"smtp:", column_ifexists("ForwardingSmtpAddress", "")),
      ""))
  | where isnotempty(DestinationMailAddress)
  | mv-expand split(DestinationMailAddress, ";")
  | extend ClientIPValues = extract_all(@'\[?(::ffff:)?(?P<IPAddress>(\d+\.\d+\.\d+\.\d+)|[^\]]+)\]?([-:](?P<Port>\d+))?', dynamic(["IPAddress", "Port"]), ClientIP)[0]
  | extend ClientIP = tostring(ClientIPValues[0]), Port = tostring(ClientIPValues[1])
  | summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), DistinctUserCount = dcount(UserId), UserId = make_set(UserId, 250), Ports = make_set(Port, 250), EventCount = count() by tostring(DestinationMailAddress), ClientIP
  | where DistinctUserCount > 1 and EndTime > ago(queryfrequency)
  | mv-expand UserId to typeof(string)
  | extend AccountName = tostring(split(UserId, "@")[0]), AccountUPNSuffix = tostring(split(UserId, "@")[1])
  | extend Account_0_Name = AccountName
  | extend Account_0_UPNSuffix = AccountUPNSuffix
  | extend IP_0_Address = ClientIP
  ```
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountName
      - identifier: UPNSuffix
        columnName: AccountUPNSuffix
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: ClientIP
version: 2.0.1
kind: Scheduled
---
