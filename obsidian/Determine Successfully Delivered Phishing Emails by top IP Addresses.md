---
id: cdac93ef-56c0-45bf-9e7f-9cbf0ad06567
name: Determine Successfully Delivered Phishing Emails by top IP Addresses
description: "This query identifies phishing emails sent that were successfully delivered, by top IP addressess. cutoff default value is 5, adjust the value as needed. \n"
requiredDataConnectors:
  - connectorId: OfficeATP
    dataTypes:
      - EmailEvents
tactics:
  - InitialAccess
relevantTechniques:
  - T1566
query: "```kusto\n// Adjust the cutoff as needed \nlet cutoff = 5;\nEmailEvents\n| where ThreatTypes has \"Malware\" or ThreatTypes has \"Phish\" \n| summarize count() by SenderIPv4 \n| where count_ > cutoff\n| join kind=inner EmailEvents on SenderIPv4  \n| where DeliveryAction =~ \"Delivered\"\n| extend Name = tostring(split(SenderFromAddress, '@', 0)[0]), UPNSuffix = tostring(split(SenderFromAddress, '@', 1)[0])\n| extend Account_0_Name = Name\n| extend Account_0_UPNSuffix = UPNSuffix\n| extend IP_0_Address = SenderIPv4\n| extend MailBox_0_MailboxPrimaryAddress = RecipientEmailAddress\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: Name
      - identifier: UPNSuffix
        columnName: UPNSuffix
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: SenderIPv4
  - entityType: MailBox
    fieldMappings:
      - identifier: MailboxPrimaryAddress
        columnName: RecipientEmailAddress
version: 1.0.1
---

