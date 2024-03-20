---
id: 0a8f410d-38b5-4d75-90da-32b472b97230
name: Non-owner mailbox login activity
description: |
  'Finds non-owner mailbox access by admin/delegate permissions. Whitelist valid users and check others for unauthorized access.'
description-detailed: "'This will help you determine if mailbox access observed with Admin/Delegate Logontype. \nThe logon type indicates mailbox accessed from non-owner user. Exchange allows Admin \nand delegate permissions to access other user's inbox.\nIf your organization has valid admin, delegate access given to users, you can whitelist those and investigate other results.\nReferences: https://docs.microsoft.com/office/office-365-management-api/office-365-management-activity-api-schema#logontype'\n"
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
tags:
  - Solorigate
  - NOBELIUM
query: "```kusto\nOfficeActivity\n| where OfficeWorkload == \"Exchange\"\n| where Operation == \"MailboxLogin\" and Logon_Type != \"Owner\" \n| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), count() by Operation, OrganizationName, UserType, UserId, MailboxOwnerUPN, Logon_Type, ClientIP\n| extend AccountName = tostring(split(UserId, \"@\")[0]), AccountUPNSuffix = tostring(split(UserId, \"@\")[1])\n| extend IP_0_Address = ClientIP\n| extend Account_0_Name = AccountName\n| extend Account_0_UPNSuffix = AccountUPNSuffix\n```"
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
---

