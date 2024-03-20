---
id: 40d8ad3e-67b4-11ec-90d6-0242ac120003
name: ApexOne - Channel type by users
description: |
  'Shows channel type.'
severity: Medium
requiredDataConnectors:
  - connectorId: TrendMicroApexOne
    dataTypes:
      - TMApexOneEvent
  - connectorId: TrendMicroApexOneAma
    dataTypes:
      - TMApexOneEvent
tactics:
  - CommandandControl
relevantTechniques:
  - T1071
query: "```kusto\nTMApexOneEvent\n| where TimeGenerated > ago(24h)\n| where EventMessage has \"Data Loss Prevention\"\n| extend DeviceCustomNumber3 = coalesce(\n                                  column_ifexists(\"FieldDeviceCustomNumber3\", long(null)),\n                                  DeviceCustomNumber3,\n                                  long(null)\n                              )\n| where isnotempty(DeviceCustomNumber3)\n| extend DlpAction = case(\nDeviceCustomNumber3 == \"65535\", \"Not available\",\nDeviceCustomNumber3 == \"0\", \"Removable storage\", \nDeviceCustomNumber3 == \"1\", \"SMB\",\nDeviceCustomNumber3 == \"2\", \"Email\",\nDeviceCustomNumber3 == \"3\", \"IM\", \nDeviceCustomNumber3 == \"4\", \"FTP\",\nDeviceCustomNumber3 == \"5\", \"HTTP\",\nDeviceCustomNumber3 == \"6\", \"HTTPS\", \nDeviceCustomNumber3 == \"7\", \"PGP\",\nDeviceCustomNumber3 == \"8\", \"Data recorders\",\nDeviceCustomNumber3 == \"9\", \"Printer\", \nDeviceCustomNumber3 == \"10\", \"Clipboard\",\nDeviceCustomNumber3 == \"11\", \"Sync\",\nDeviceCustomNumber3 == \"12\", \"P2P\",\nDeviceCustomNumber3 == \"13\", \"Webmail\", \nDeviceCustomNumber3 == \"14\", \"Document management\",\nDeviceCustomNumber3 == \"15\", \"Cloud storage\",\nDeviceCustomNumber3 == \"121\", \"SMTP email\",\nDeviceCustomNumber3 == \"122\", \"Exchange Client Mail\", \nDeviceCustomNumber3 == \"123\", \"Lotus Note Email\",\nDeviceCustomNumber3 == \"130\", \"Webmail (Yahoo! Mail)\",\nDeviceCustomNumber3 == \"131\", \"Webmail (Hotmail)\",\nDeviceCustomNumber3 == \"132\", \"Webmail (Gmail)\",\nDeviceCustomNumber3 == \"133\", \"Webmail (AOL Mail)\",\nDeviceCustomNumber3 == \"140\", \"IM (MSN)\",\nDeviceCustomNumber3 == \"141\", \"IM (AIM)\",\nDeviceCustomNumber3 == \"142\", \"IM (Yahoo Messenger)\",\nDeviceCustomNumber3 == \"143\", \"IM (Skype)\",\nDeviceCustomNumber3 == \"191\", \"P2P (BitTorrent)\",\nDeviceCustomNumber3 == \"192\", \"P2P (EMule)\",\nDeviceCustomNumber3 == \"193\", \"P2P (Winny)\",\nDeviceCustomNumber3 == \"194\", \"P2P (HTCSYN)\",\nDeviceCustomNumber3 == \"195\", \"P2P (iTunes)\",\nDeviceCustomNumber3 == \"196\", \"Cloud storage (DropBox)\",\nDeviceCustomNumber3 == \"197\", \"Cloud storage (Box)\",\nDeviceCustomNumber3 == \"198\", \"Cloud storage (Google Drive)\",\nDeviceCustomNumber3 == \"199\", \"Cloud storage (OneDrive)\",\nDeviceCustomNumber3 == \"200\", \"Cloud storage (SugarSync)\",\nDeviceCustomNumber3 == \"201\", \"Cloud storage (Hightail)\",\nDeviceCustomNumber3 == \"202\", \"IM (QQ)\",\nDeviceCustomNumber3 == \"203\", \"Webmail (other)\",\nDeviceCustomNumber3 == \"204\", \"Cloud storage (Evernote)\",\nDeviceCustomNumber3 == \"211\", \"Document management (SharePoint)\",\n\"unknown\")\n| summarize ChannelType = count() by DlpAction, DstUserName\n| extend AccountCustomEntity = DstUserName\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountCustomEntity
---

