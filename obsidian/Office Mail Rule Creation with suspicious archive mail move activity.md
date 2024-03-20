---
id: f50a26d7-ffdb-4471-90b9-3be78c60e4f2
name: Office Mail Rule Creation with suspicious archive mail move activity
description: |
  'Hunting query to detect new inbox rule creation with activity of mail moved from inbox to archive folder within 12minutes.Though such activities could be legitimate some attackers may use these techniques to perform email diversion attack.'
description_detailed: |
  'Hunting query to detect new inbox rule creation with activity of mail moved from inbox to archive folder within 12minutes.Though such activities could be legitimate some attackers may use these techniques to perform email diversion attack.
  Reference: https://redcanary.com/blog/email-payroll-diversion-attack/'
requiredDataConnectors:
  - connectorId: Office365
    dataTypes:
      - OfficeActivity (Exchange)
tactics:
  - Collection
  - Exfiltration
relevantTechniques:
  - T1114
  - T1020
query: "```kusto\n// New Inbox rule creation\nlet Inboxrulecreation=\nOfficeActivity\n| where Operation =~ \"New-InboxRule\"\n| where ResultStatus =~ \"Succeeded\"\n| extend Inboxrulecreationtime = TimeGenerated  \n| project Operation, _ResourceId, _SubscriptionId, UserId, Inboxrulecreationtime, ActorIpAddress\n;\n// Email Sent Succeeded\nlet Emailsent=\nOfficeActivity\n| extend Emailsenttime = TimeGenerated\n| where Operation =~ \"Send\"\n| where ResultStatus =~ \"Succeeded\"\n| extend Subject = tostring(parse_json(Item).[\"Subject\"])\n| summarize count() by UserId, Emailsenttime, OriginatingServer, Subject, ActorIpAddress\n;\n//Email moved from Sent to Archive folder\nlet Emailmoved=\nOfficeActivity\n| extend Emailmovedtime = TimeGenerated\n| where Operation =~ \"move\"\n| where OfficeWorkload =~ \"Exchange\"\n| where ResultStatus =~ \"Succeeded\"\n|  extend OriginFolderPath = tostring(parse_json(Folder).[\"Path\"])\n| extend DestFolderPath = tostring(parse_json(DestFolder).[\"Path\"])\n| extend Subject = tostring(parse_json(AffectedItems)[0].Subject)\n| where OriginFolderPath contains \"Sent\"\n| where DestFolderPath contains \"Archive\"\n| project  OriginFolderPath, DestFolderPath, UserId, Emailmovedtime, OriginatingServer, Subject\n;\nInboxrulecreation\n| join kind=inner Emailsent on UserId\n| where abs(datetime_diff('minute',Inboxrulecreationtime, Emailsenttime)) <=12\n| join kind=inner Emailmoved on UserId,Subject\n| where abs(datetime_diff('minute', Emailsenttime, Emailmovedtime)) <=12\n// Email is Sent before Moving to Archive Folder\n| where Emailsenttime <= Emailmovedtime\n| extend AccountCustomEntity = UserId\n| extend IPCustomEntity = ActorIpAddress\n| extend HostCustomEntity = OriginatingServer\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountCustomEntity
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPCustomEntity
  - entityType: Host
    fieldMappings:
      - identifier: FullName
        columnName: HostCustomEntity
---

