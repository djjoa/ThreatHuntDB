---
id: ab619659-ab7c-4ca4-be0c-ca71a07bf4cd
name: Account brute force
description: |
  Query #1: Look for public IP addresses that failed to logon to a computer multiple times, using multiple accounts, and eventually succeeded.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceLogonEvents
query: "```kusto\nDeviceLogonEvents\n| where isnotempty(RemoteIP) \n    and AccountName !endswith \"$\"\n    and RemoteIPType == \"Public\"\n| extend Account=strcat(AccountDomain, \"\\\\\", AccountName)\n| summarize \n    Successful=countif(ActionType == \"LogonSuccess\"),\n    Failed = countif(ActionType == \"LogonFailed\"),\n    FailedAccountsCount = dcountif(Account, ActionType == \"LogonFailed\"),\n    SuccessfulAccountsCount = dcountif(Account, ActionType == \"LogonSuccess\"),\n    FailedAccounts = makeset(iff(ActionType == \"LogonFailed\", Account, \"\"), 5),\n    SuccessfulAccounts = makeset(iff(ActionType == \"LogonSuccess\", Account, \"\"), 5)\n    by DeviceName, RemoteIP, RemoteIPType\n| where Failed > 10 and Successful > 0 and FailedAccountsCount > 2 and SuccessfulAccountsCount == 1\n```"
---

