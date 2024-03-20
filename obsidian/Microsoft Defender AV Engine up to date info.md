---
id: 02BE358B-8733-46B7-8E3D-624B1F918237
name: Microsoft Defender AV Engine up to date info
description: |
  'Provides the Engine version and total count of up to date devices, not up to date devices and count of devices whose status is not available relevant to the Engine version.'
requiredDataConnectors: []
tactics: []
relevantTechniques: []
query: "```kusto\nlet expiringPublishdate = ago(8d);\nDeviceTvmInfoGathering\n| extend DataRefreshTimestamp = Timestamp,    \nAvIsEngineUpToDateTemp = tostring(AdditionalFields.AvIsEngineUptodate),   \nAvSignatureDataRefreshTime = todatetime(AdditionalFields.AvSignatureDataRefreshTime), \nAvSignaturePublishTime = todatetime(AdditionalFields.AvSignaturePublishTime),    \nAvEngineVersion =  tostring(AdditionalFields.AvEngineVersion)\n| extend AvIsEngineUpToDate = iif(((((isempty(AvIsEngineUpToDateTemp)\nor (isnull(AvSignatureDataRefreshTime)))\nor (isnull(AvSignaturePublishTime)))\nor (AvSignatureDataRefreshTime < expiringPublishdate))\nor (AvSignaturePublishTime < expiringPublishdate)), \"Unknown\", tostring(AvIsEngineUpToDateTemp))  \n| extend AvEngineVersion = iif(AvEngineVersion == \"\", \"Unknown\", AvEngineVersion)\n| project DeviceId, DeviceName,  OSPlatform, AvEngineVersion, DataRefreshTimestamp, AvIsEngineUpToDate, AvSignaturePublishTime, AvSignatureDataRefreshTime\n| summarize DeviceCount = count(), DataRefreshTimestamp = max(DataRefreshTimestamp), EngineUpToDateDeviceCount = countif(AvIsEngineUpToDate == \"true\"), EngineNotUpToDateDeviceCount = countif(AvIsEngineUpToDate == \"false\"), EngineNotAvailableDeviceCount = countif(AvIsEngineUpToDate == \"Unknown\") by OSPlatform,AvEngineVersion\n```"
---

