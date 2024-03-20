---
id: a4dbc292-87eb-11ec-a8a3-0242ac120002
name: Decoy User Account Authentication Attempt
description: "'The query detects authentication attempts from a decoy user account. \nA decoy user account is explicitly created and monitored to alert the SOC, indicating a malicious activity when the account is in use.'\n"
requiredDataConnectors:
  - connectorId: SecurityEvents
    dataTypes:
      - SecurityEvent
  - connectorId: WindowsSecurityEvents
    dataTypes:
      - SecurityEvent
tactics:
  - LateralMovement
relevantTechniques:
  - T1021
query: "```kusto\n// Enter a reference list of decoy users (usernames) \"Case Sensitive\"\n   let DecoyUserNameList = dynamic ([\"DecoyUser1\",\"DecoyUser2\"]);\nSecurityEvent\n | where TargetUserName in (DecoyUserNameList)\n | where EventID in (4624,4625)\n | summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) by EventID, Computer, TargetUserName, LogonTypeName, IpAddress\n | extend Account_0_Name = TargetUserName\n | extend Host_0_HostName = Computer\n | extend IP_0_Address = IpAddress  \n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: TargetUserName
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: Computer
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IpAddress
version: 2.0.2
kind: Scheduled
---

