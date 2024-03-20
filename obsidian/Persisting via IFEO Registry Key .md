---
id: f82c89fa-c969-4d12-832f-04d55d14522c
name: Persisting via IFEO Registry Key
description: |
  'This query detects instances where IFEO registry keys were created and deleted frequently within a short period of time.
  This technique is used by adversaries to persist on a system by creating a registry key under the Image File Execution Options registry key.
  https://goayxh.medium.com/malware-persistence-image-file-execution-options-injection-ifeo-5aa0e81086f0'
severity: Medium
requiredDataConnectors:
  - connectorId: SecurityEvents
    dataTypes:
      - SecurityEvent
  - connectorId: WindowsSecurityEvents
    dataTypes:
      - SecurityEvents
  - connectorId: WindowsForwardedEvents
    dataTypes:
      - WindowsEvent
tactics:
  - Persistence
relevantTechniques:
  - T1546.012
tags:
  - Solorigate
  - NOBELIUM
query: "```kusto\n(union isfuzzy=true\n(\nSecurityEvent\n| where EventID == 4657\n| where ObjectName has_all (\"\\\\REGISTRY\\\\MACHINE\", \"Image File Execution Options\")\n| where ObjectName !endswith \"Image File Execution Options\"\n| summarize Count=count() by Computer, Account, ObjectName\n| top 10 by Count desc \n| extend AccountCustomEntity = Account, HostCustomEntity = Computer\n),\n(\nWindowsEvent\n| where EventID == 4657 and EventData has_all (\"\\\\REGISTRY\\\\MACHINE\", \"Image File Execution Options\")\n| extend ObjectName = tostring(EventData.ObjectName)\n| where ObjectName has_all (\"\\\\REGISTRY\\\\MACHINE\", \"Image File Execution Options\")\n| where ObjectName !endswith \"Image File Execution Options\"\n| extend Account =  strcat(tostring(EventData.SubjectDomainName),\"\\\\\", tostring(EventData.SubjectUserName))\n| summarize Count=count() by Computer, Account, ObjectName\n| top 10 by Count desc \n| extend AccountCustomEntity = Account, HostCustomEntity = Computer\n),\n(\nEvent\n| where Source =~ \"Microsoft-Windows-Sysmon\"\n| where EventID in (12, 13)\n| extend EventData = parse_xml(EventData).DataItem.EventData.Data\n| mv-expand bagexpansion=array EventData\n| evaluate bag_unpack(EventData)\n| extend Key = tostring(column_ifexists('@Name', \"\")), Value = column_ifexists('#text', \"\")\n| evaluate pivot(Key, any(Value), TimeGenerated, Source, EventLog, Computer, EventLevel, EventLevelName, EventID, UserName, RenderedDescription, MG, ManagementGroupName, Type, _ResourceId)\n| where TargetObject has_all (\"HKLM\", \"Image File Execution Options\")\n| summarize Count=count() by Computer, UserName, tostring(TargetObject)\n| top 10 by Count desc\n| extend AccountCustomEntity = UserName, HostCustomEntity = Computer\n),\n(\nimRegistry\n| where RegistryKey has_all (\"HKEY_LOCAL_MACHINE\", \"Image File Execution Options\")\n| summarize Count=count() by Dvc, Username, RegistryKey\n| top 10 by Count desc\n| extend AccountCustomEntity = Username, HostCustomEntity = Dvc\n)\n)\n| extend NTDomain = tostring(split(AccountCustomEntity, '\\\\', 0)[0]), Name = tostring(split(AccountCustomEntity, '\\\\', 1)[0])\n| extend HostName = tostring(split(HostCustomEntity, '.', 0)[0]), DnsDomain = tostring(strcat_array(array_slice(split(HostCustomEntity, '.'), 1, -1), '.'))\n| extend Account_0_Name = Name\n| extend Account_0_NTDomain = NTDomain\n| extend Host_0_HostName = HostName\n| extend Host_0_DnsDomain = DnsDomain\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: Name
      - identifier: NTDomain
        columnName: NTDomain
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostName
      - identifier: DnsDomain
        columnName: DnsDomain
version: 1.0.1
---

