---
id: f2367171-1514-4c67-88ef-27434b6a1093
name: SharePointFileOperation via devices with previously unseen user agents
description: |
  'Tracking via user agent is one way to differentiate between types of connecting device.
  In homogeneous enterprise environments the user agent associated with an attacker device may stand out as unusual.'
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - SigninLogs
  - connectorId: Office365
    dataTypes:
      - OfficeActivity (SharePoint)
tactics:
  - Exfiltration
relevantTechniques:
  - T1030
query: "```kusto\nlet starttime = todatetime('{{StartTimeISO}}');\nlet endtime = todatetime('{{EndTimeISO}}');\nlet lookback = starttime - 14d;\nlet MINIMUM_BLOCKS = 10;\nlet SUCCESS_THRESHOLD = 0.2;\nlet HistoricalActivity = \nSigninLogs\n| where TimeGenerated > lookback\n| where isnotempty(UserAgent)\n| summarize SuccessfulSignins=countif(ResultType==\"0\"), BlockedSignins=countif(ResultType==\"50053\") by UserAgent\n| extend SuccessBlockRatio = 1.00 * SuccessfulSignins / BlockedSignins\n| where SuccessBlockRatio < SUCCESS_THRESHOLD\n| where BlockedSignins > MINIMUM_BLOCKS \n;\nOfficeActivity\n| where TimeGenerated between (starttime .. endtime)\n| where  RecordType == \"SharePointFileOperation\"\n| where Operation in (\"FileDownloaded\", \"FileUploaded\")\n| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), RecentFileActivities=count() by UserAgent, UserId, ClientIP, Site_Url\n| join kind=innerunique (HistoricalActivity) on UserAgent\n| project-away UserAgent1\n| extend AccountName = tostring(split(UserId, \"@\")[0]), AccountUPNSuffix = tostring(split(UserId, \"@\")[1])\n| extend IP_0_Address = ClientIP\n| extend Account_0_Name = AccountName\n| extend Account_0_UPNSuffix = AccountUPNSuffix\n| extend URL_0_Url = Site_Url\n```"
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: ClientIP
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountName
      - identifier: UPNSuffix
        columnName: AccountUPNSuffix
  - entityType: URL
    fieldMappings:
      - identifier: Url
        columnName: Site_Url
version: 2.0.1
---

