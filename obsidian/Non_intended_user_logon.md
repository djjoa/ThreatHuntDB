---
id: ef645ae9-da22-4ebe-b2ad-c3ad024b807c
name: Non_intended_user_logon
description: |
  Under some circumstances it is only allowed that users
  from country X logon to devices from country X.
  This query finds logon from users from other countries than X.
  The query requires a property to identify the users from
  country X. In this example a specific Email Address.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceInfo
      - IdentityInfo
      - DeviceLogonEvents
query: "```kusto\nlet relevant_computers=\nDeviceInfo\n| where MachineGroup == \"My_MachineGroup\" \n| summarize make_list(DeviceName);\nlet relevant_users=\nIdentityInfo\n| where MailAddress endswith \"@allowed.users\"\n| summarize make_list(AccountName);\nDeviceLogonEvents\n| where Timestamp > ago(1d)\n| where DeviceName in (relevant_computers)\n| where AccountName !in (relevant_users)\n| project DeviceName, AccountName\n```"
---

