---
id: f090f8f4a-b986-42d2-b536-e0795c723e25
name: Known Nylon Typhoon Registry modifications patterns
description: |
  'This query identifies instances where malware intentionally configures the browser settings for its use by modifying the following registry entries by Nylon Typhoon threat actor.'
severity: Medium
requiredDataConnectors:
  - connectorId: SecurityEvents
    dataTypes:
      - SecurityEvent
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceRegistryEvents
  - connectorId: WindowsSecurityEvents
    dataTypes:
      - SecurityEvents
  - connectorId: WindowsForwardedEvents
    dataTypes:
      - WindowsEvent
queryFrequency: 1d
queryPeriod: 1d
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Persistence
relevantTechniques:
  - T1546.012
query: "```kusto\nlet reg_paths = dynamic([\"HKEY_CURRENT_USER\\\\Software\\\\Microsoft\\\\Internet Explorer\\\\Main\", \n                        \"HKEY_CURRENT_USER\\\\Software\\\\Microsoft\\\\Internet Explorer\\\\Recovery\", \n                        \"HKEY_CURRENT_USER\\\\Software\\\\Microsoft\\\\Internet Explorer\\\\Privacy\", \n                        \"HKEY_CURRENT_USER\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet Settings\\\\ZoneMap\"\n                        ]);\nlet reg_keys = dynamic([\"Start Page\", \"DisableFirstRunCustomize\", \"RunOnceComplete\", \"RunOnceHasShown\", \"Check_Associations\", \"AutoRecover\", \"ClearBrowsingHistoryOnExit\", \"Completed\", \"IEHarden\"]);\n(union isfuzzy=true\n(\nSecurityEvent\n| where EventID == 4657\n| where ObjectName has_any (reg_paths) and ObjectValueName has_any (reg_keys)\n| summarize Count=count() by Computer, Account, ObjectName\n| extend AccountCustomEntity = Account, HostCustomEntity = Computer\n),\n(\nWindowsEvent\n| where EventID == 4657 and EventData  has_any (reg_paths) and EventData has_any (reg_keys)\n| extend ObjectName = tostring(EventData.ObjectName)\n| extend ObjectValueName = tostring(EventData.ObjectValueName)\n| where ObjectName has_any (reg_paths) and ObjectValueName has_any (reg_keys)\n| extend Account =  strcat(tostring(EventData.SubjectDomainName),\"\\\\\", tostring(EventData.SubjectUserName))\n| summarize Count=count() by Computer, Account, ObjectName\n| extend AccountCustomEntity = Account, HostCustomEntity = Computer\n),\n(\nEvent\n| where Source == \"Microsoft-Windows-Sysmon\"\n| where EventID in (12, 13)\n| extend EventData = parse_xml(EventData).DataItem.EventData.Data\n| mv-expand bagexpansion=array EventData\n| evaluate bag_unpack(EventData)\n| extend Key=tostring(['@Name']), Value=['#text']\n| evaluate pivot(Key, any(Value), TimeGenerated, Source, EventLog, Computer, EventLevel, EventLevelName, EventID, UserName, RenderedDescription, MG, ManagementGroupName, Type, _ResourceId)\n| where TargetObject has_any (reg_paths) and TargetObject has_any (reg_keys)\n| summarize Count=count() by Computer, UserName, tostring(TargetObject)\n| extend AccountCustomEntity = UserName, HostCustomEntity = Computer\n),\n(\nimRegistry\n| where RegistryKey has_any (reg_paths) and RegistryValue has_any (reg_keys)\n| summarize Count=count() by Dvc, Username, RegistryKey\n| extend AccountCustomEntity = Username, HostCustomEntity = Dvc\n)\n)\n| extend NTDomain = tostring(split(AccountCustomEntity, '\\\\', 0)[0]), Name = tostring(split(AccountCustomEntity, '\\\\', 1)[0])\n| extend HostName = tostring(split(HostCustomEntity, '.', 0)[0]), DnsDomain = tostring(strcat_array(array_slice(split(HostCustomEntity, '.'), 1, -1), '.'))\n| extend Account_0_Name = Name\n| extend Account_0_NTDomain = NTDomain\n| extend Host_0_HostName = HostName\n| extend Host_0_DnsDomain = DnsDomain\n```"
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

