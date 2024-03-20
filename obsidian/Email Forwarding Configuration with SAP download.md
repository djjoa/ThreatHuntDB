---
id: 0576750e-6b61-4545-845f-f5b8f29a0cc4
name: Email Forwarding Configuration with SAP download
description: |
  'This query detects external email forwarding with SAP download for sensitive financial transactions. Such activity by attackers may lead to financial gain, IP theft, or operational disruption.'
description_detailed: |
  'This query could help detect any external email forwarding configuration activity with SAP download for sensitive financial transaction related keywords. Attackers may perform such operation for financial gain, Intellectual Property theft or to cause disruption of operation to an organization.'
requiredDataConnectors:
  - connectorId: SAP
    dataTypes:
      - SAPAuditLog
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - EmailEvents
  - connectorId: Office365
    dataTypes:
      - OfficeActivity
tactics:
  - InitialAccess
  - Collection
  - Exfiltration
relevantTechniques:
  - T1078
  - T1114
  - T1020
query: "```kusto\nlet Keywords = dynamic([\"payroll\", \"invoice\", \"payment\", \"statement\", \"confidential\", \"bank account\", \"wire\", \"wire transfer\"]);\nEmailEvents\n| extend Account = tostring(split(SenderFromAddress, '@', 0)[0]), UPNSuffix = tostring(split(SenderFromAddress, '@', 1)[0])\n| project NetworkMessageId, Account, RecipientEmailAddress, SenderIPv4, Subject, EmailAction, DeliveryLocation, TenantId\n| join kind=innerunique \n(OfficeActivity \n| where OfficeWorkload =~ \"Exchange\"\n| where Operation in~ (\"Set-Mailbox\", \"New-InboxRule\", \"Set-InboxRule\")\n| where Parameters has_any (\"ForwardTo\", \"RedirectTo\", \"ForwardingSmtpAddress\")\n| extend Events=todynamic(Parameters)\n| where UserId has \"@\"\n| extend Account = tostring(split(UserId, '@', 0)[0]), UPNSuffix = tostring(split(UserId, '@', 1)[0])\n| parse Events  with * \"SubjectContainsWords\" SubjectContainsWords '}'*\n| parse Events  with * \"BodyContainsWords\" BodyContainsWords '}'*\n| parse Events  with * \"SubjectOrBodyContainsWords\" SubjectOrBodyContainsWords '}'*\n| where SubjectContainsWords has_any (Keywords) or BodyContainsWords has_any (Keywords) or SubjectOrBodyContainsWords has_any (Keywords)\n| extend ClientIPAddress = case( ClientIP has \".\", tostring(split(ClientIP,\":\")[0]), ClientIP has \"[\", tostring(trim_start(@'[[]',tostring(split(ClientIP,\"]\")[0]))), ClientIP )\n| extend Keyword = iff(isnotempty(SubjectContainsWords), SubjectContainsWords, (iff(isnotempty(BodyContainsWords),BodyContainsWords,SubjectOrBodyContainsWords )))\n| extend RuleDetail = case(OfficeObjectId contains '/' , tostring(split(OfficeObjectId, '/')[-1]) , tostring(split(OfficeObjectId, '\\\\')[-1]))\n| summarize count(), StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated) by  UserId, ClientIPAddress, ResultStatus, Keyword, OriginatingServer, OfficeObjectId, RuleDetail,Account) \non Account\n| join kind=inner \n(\nSAPAuditLog \n| where MessageID == \"AUY\" //AUY= Download bytes\n| extend ByteCount= toint(replace_string(replace_string(Variable1, \".\",\"\"), \",\",\"\")), Code=Variable2, Path= Variable3\n| summarize DownloadsByUser = count(), Paths= make_set(Variable3, 10), ByteCount=sum(ByteCount) by SystemID, ClientID, User, TerminalIPv6, Email, Host, TransactionCode, Instance\n| where Paths has_any (Keywords)\n) on $left.Account == $right.User, $left.RecipientEmailAddress == $right. Email\n| project StartTimeUtc, Account, SenderIPv4, Email, Host, Keyword, NetworkMessageId, OfficeObjectId, Paths, Subject, SystemID, TenantId, ClientID, DeliveryLocation, TransactionCode\n| extend UserName = tostring(split(Account, '@', 0)[0]), UPNSuffix = tostring(split(Account, '@', 1)[0])\n| extend Account_0_Name = UserName\n| extend Account_0_UPNSuffix = UPNSuffix\n| extend IP_0_Address = SenderIPv4\n| extend Host_0_HostName = Host\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: UserName
      - identifier: UPNSuffix
        columnName: UPNSuffix
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: Host
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: SenderIPv4
version: 1.0.0
---

