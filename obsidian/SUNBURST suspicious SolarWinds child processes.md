---
id: 4a3073ac-7383-48a9-90a8-eb6716183a54
name: SUNBURST suspicious SolarWinds child processes
description: |
  'Identifies suspicious child processes of SolarWinds.Orion.Core.BusinessLayer.dll that may be evidence of the SUNBURST backdoor'
severity: Medium
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
tactics:
  - Execution
  - Persistence
tags:
  - Solorigate
  - NOBELIUM
query: "```kusto\nlet excludeProcs = dynamic([@\"\\SolarWinds\\Orion\\APM\\APMServiceControl.exe\", @\"\\SolarWinds\\Orion\\ExportToPDFCmd.Exe\", @\"\\SolarWinds.Credentials\\SolarWinds.Credentials.Orion.WebApi.exe\", @\"\\SolarWinds\\Orion\\Topology\\SolarWinds.Orion.Topology.Calculator.exe\", @\"\\SolarWinds\\Orion\\Database-Maint.exe\", @\"\\SolarWinds.Orion.ApiPoller.Service\\SolarWinds.Orion.ApiPoller.Service.exe\", @\"\\Windows\\SysWOW64\\WerFault.exe\"]);\nDeviceProcessEvents\n| where InitiatingProcessFileName =~ \"solarwinds.businesslayerhost.exe\"\n| where not(FolderPath has_any (excludeProcs))\n| extend\n    timestamp = TimeGenerated,\n    AccountCustomEntity = iff(isnotempty(InitiatingProcessAccountUpn), InitiatingProcessAccountUpn, InitiatingProcessAccountName),\n    HostName = tostring(split(DeviceName, '.', 0)[0]), DnsDomain = tostring(strcat_array(array_slice(split(DeviceName, '.'), 1, -1), '.')),\n    AlgorithmCustomEntity = \"MD5\",FileHashCustomEntity = MD5\n|extend Name = tostring(split(AccountCustomEntity, '@', 0)[0]), UPNSuffix = tostring(split(AccountCustomEntity, '@', 1)[0])    \n| extend Account_0_Name = Name\n| extend Account_0_UPNSuffix = UPNSuffix\n| extend Host_0_HostName = HostName\n| extend Host_0_DnsDomain = DnsDomain \n| extend FileHash_0_Algorithm = AlgorithmCustomEntity\n| extend FileHash_0_Value = FileHashCustomEntity \n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: Name
      - identifier: UPNSuffix
        columnName: UPNSuffix
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostName
      - identifier: DnsDomain
        columnName: DnsDomain
  - entityType: FileHash
    fieldMappings:
      - identifier: Algorithm
        columnName: AlgorithmCustomEntity
      - identifier: Value
        columnName: FileHashCustomEntity
version: 1.0.1
---

