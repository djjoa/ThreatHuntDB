---
id: 4EBA78B0-8E8E-4E9A-9AFF-160372BDD201
name: Microsoft Defender AV Platform up to date information
description: |
  'Provides the Platform version and total count of up to date devices, not up to date devices and count of devices whose status is not available relevant to the Platform version.'
requiredDataConnectors: []
tactics: []
relevantTechniques: []
query: "```kusto\nlet expiringPublishdate = ago(8d);\nDeviceTvmInfoGathering\n| extend DataRefreshTimestamp = Timestamp,    \nAvIsPlatformUpToDateTemp=tostring(AdditionalFields.AvIsPlatformUptodate),\nAvSignatureDataRefreshTime = todatetime(AdditionalFields.AvSignatureDataRefreshTime), \nAvSignaturePublishTime = todatetime(AdditionalFields.AvSignaturePublishTime),\nAvPlatformVersion =  tostring(AdditionalFields.AvPlatformVersion) \n| extend AvIsPlatformUpToDate = iif(((((isempty(AvIsPlatformUpToDateTemp)\nor (isnull(AvSignatureDataRefreshTime)))\nor (isnull(AvSignaturePublishTime)))\nor (AvSignatureDataRefreshTime < expiringPublishdate))\nor (AvSignaturePublishTime < expiringPublishdate)), \"Unknown\", tostring(AvIsPlatformUpToDateTemp)) \n| extend AvPlatformVersion = iif(AvPlatformVersion == \"\", \"Unknown\", AvPlatformVersion)\n| project DeviceId, DeviceName,  OSPlatform, AvPlatformVersion, DataRefreshTimestamp, AvIsPlatformUpToDate, AvSignaturePublishTime, AvSignatureDataRefreshTime\n| summarize DeviceCount = count(), DataRefreshTimestamp = max(DataRefreshTimestamp), PlatformUpToDateDeviceCount = countif(AvIsPlatformUpToDate == \"true\"),  PlatformNotUpToDateDeviceCount = countif(AvIsPlatformUpToDate == \"false\"),  PlatformNotAvailableDeviceCount = countif(AvIsPlatformUpToDate == \"Unknown\") by OSPlatform,AvPlatformVersion\n```"
---

