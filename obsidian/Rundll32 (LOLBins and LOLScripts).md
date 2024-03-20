---
id: c2074fce-b5ba-4c0a-9332-d08b8fc43c53
name: Rundll32 (LOLBins and LOLScripts)
description: |
  'This detection uses Sysmon telemetry to hunt Signed Binary Proxy Execution: Rundll32 activities.'
requiredDataConnectors:
  - connectorId: SecurityEvents
    dataTypes:
      - SecurityEvent
tactics:
  - DefenseEvasion
relevantTechniques:
  - T1218.011
query: "```kusto\nEvent\n//This query uses sysmon data depending on table name used this may need updataing\n| where Source =~ \"Microsoft-Windows-Sysmon\"\n| where EventID == 1\n| extend RenderedDescription = tostring(split(RenderedDescription, \":\")[0])\n| extend EventData = parse_xml(EventData).DataItem.EventData.Data\n| mv-expand bagexpansion=array EventData\n| evaluate bag_unpack(EventData)\n| extend Key = tostring(column_ifexists('@Name', \"\")), Value = column_ifexists('#text', \"\")\n| evaluate pivot(Key, any(Value), TimeGenerated, Source, EventLog, Computer, EventLevel, EventLevelName, EventID, UserName, RenderedDescription, MG, ManagementGroupName, Type, _ResourceId)\n| extend RuleName = column_ifexists(\"RuleName\", \"\"), TechniqueId = column_ifexists(\"TechniqueId\", \"\"),  TechniqueName = column_ifexists(\"TechniqueName\", \"\")\n| parse RuleName with * 'technique_id=' TechniqueId ',' * 'technique_name=' TechniqueName\n| extend Image = column_ifexists(\"Image\", \"\")\n| where Image has \"rundll32.exe\"\n// Uncomment the next line and add your commandLine Whitelisted/ignore terms.For example \"payload.dll\"\n// | where CommandLine !contains (\"payload.dll\") \n| extend NTDomain = tostring(split(UserName, '\\\\', 0)[0]), Name = tostring(split(UserName, '\\\\', 1)[0])\n| extend HostName = tostring(split(Computer, '.', 0)[0]), DnsDomain = tostring(strcat_array(array_slice(split(Computer, '.'), 1, -1), '.'))\n| extend Account_0_Name = Name\n| extend Account_0_NTDomain = NTDomain\n| extend Host_0_HostName = HostName\n| extend Host_0_DnsDomain = DnsDomain\n```"
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

