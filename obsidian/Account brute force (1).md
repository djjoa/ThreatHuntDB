---
id: 89cc68d2-1330-40ce-aaca-5c76fc4f52b3
name: Account brute force (1)
description: |
  Query #1: Look for public IP addresses that failed to logon to a computer multiple times, using multiple accounts, and eventually succeeded.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceLogonEvents
query: "```kusto\n// Query #2: Look for machines failing to log-on to multiple machines or using multiple accounts\n// Note - RemoteDeviceName is not available in all remote logon attempts\nDeviceLogonEvents\n| where isnotempty(RemoteDeviceName)\n| extend Account=strcat(AccountDomain, \"\\\\\", AccountName)\n| summarize \n    Successful=countif(ActionType == \"LogonSuccess\"),\n    Failed = countif(ActionType == \"LogonFailed\"),\n    FailedAccountsCount = dcountif(Account, ActionType == \"LogonFailed\"),\n    SuccessfulAccountsCount = dcountif(Account, ActionType == \"LogonSuccess\"),\n    FailedComputerCount = dcountif(DeviceName, ActionType == \"LogonFailed\"),\n    SuccessfulComputerCount = dcountif(DeviceName, ActionType == \"LogonSuccess\")\n    by RemoteDeviceName\n| where\n    Successful > 0 and\n    ((FailedComputerCount > 100 and FailedComputerCount > SuccessfulComputerCount) or\n        (FailedAccountsCount > 100 and FailedAccountsCount > SuccessfulAccountsCount))\n```"
---

