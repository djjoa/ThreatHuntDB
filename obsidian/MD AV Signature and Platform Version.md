---
id: 30035880-b7af-4d5e-8617-be7f070a5c1c
name: MD AV Signature and Platform Version
description: |
  This query will identify the Microsoft Defender Antivirus Engine version and Microsoft Defender Antivirus Security Intelligence version (and timestamp), Product update version (aka Platform Update version) as well as the Microsoft Defender Antivirus Mode on the endpoint (Active, Passive, etc.).
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceTvmSecureConfigurationAssessment
tactics:
  - Vulnerability
  - Misconfiguration
query: "```kusto\nlet avmodetable = DeviceTvmSecureConfigurationAssessment\n| where ConfigurationId == \"scid-2010\" and isnotnull(Context)\n| extend avdata=parsejson(Context)\n| extend AVMode = iif(tostring(avdata[0][0]) == '0', 'Active' , iif(tostring(avdata[0][0]) == '1', 'Passive' ,iif(tostring(avdata[0][0]) == '4', 'EDR Blocked' ,'Unknown')))\n| project DeviceId, AVMode;\nDeviceTvmSecureConfigurationAssessment\n| where ConfigurationId == \"scid-2011\" and isnotnull(Context)\n| extend avdata=parsejson(Context)\n| extend AVSigVersion = tostring(avdata[0][0])\n| extend AVEngineVersion = tostring(avdata[0][1])\n| extend AVSigLastUpdateTime = tostring(avdata[0][2])\n| extend AVProductVersion = tostring(avdata[0][3]) \n| project DeviceId, DeviceName, OSPlatform, AVSigVersion, AVEngineVersion, AVSigLastUpdateTime, AVProductVersion, IsCompliant, IsApplicable\n| join avmodetable on DeviceId\n| project-away DeviceId1\n```"
---

