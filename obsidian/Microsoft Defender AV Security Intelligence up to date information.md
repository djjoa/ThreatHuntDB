---
id: 0F2179FB-BACC-4B71-80B3-29DE436E965C
name: Microsoft Defender AV Security Intelligence up to date information
description: |
  'Provides the Security Intelligence version and total count of up to date devices, not up to date devices and count of devices whose status is not available relevant to the security intelligence version.'
requiredDataConnectors: []
tactics: []
relevantTechniques: []
query: "```kusto\nlet expiringPublishdate = ago(8d);\nDeviceTvmInfoGathering\n| extend DataRefreshTimestamp = Timestamp, \nAvIsSignatureUpToDateTemp = tostring(AdditionalFields.AvIsSignatureUptoDate),\nAvSignatureDataRefreshTime = todatetime(AdditionalFields.AvSignatureDataRefreshTime), \nAvSignaturePublishTime = todatetime(AdditionalFields.AvSignaturePublishTime),\nAvSignatureVersion =  tostring(AdditionalFields.AvSignatureVersion)  \n| extend AvIsSignatureUpToDate = iif(((((isempty(AvIsSignatureUpToDateTemp)\nor (isnull(AvSignatureDataRefreshTime)))\nor (isnull(AvSignaturePublishTime)))\nor (AvSignaturePublishTime < expiringPublishdate))\nor (AvIsSignatureUpToDateTemp == True\nand AvSignaturePublishTime < expiringPublishdate)), \"Unknown\", tostring(AvIsSignatureUpToDateTemp))\n| extend AvSecurityIntelVersion = iif(AvSignatureVersion == \"\", \"Unknown\", AvSignatureVersion)\n| project DeviceId, DeviceName, OSPlatform, AvSecurityIntelVersion,  DataRefreshTimestamp, AvIsSignatureUpToDate, AvSignaturePublishTime, AvSignatureDataRefreshTime\n| summarize DeviceCount = count(), DataRefreshTimestamp = max(DataRefreshTimestamp), SecurityIntelUpToDateDeviceCount = countif(AvIsSignatureUpToDate == \"true\"), SecurityIntelNotUpToDateDeviceCount = countif(AvIsSignatureUpToDate == \"false\"), SecurityIntelNotAvailableDeviceCount = countif(AvIsSignatureUpToDate == \"Unknown\") by OSPlatform,AvSecurityIntelVersion\n```"
---

