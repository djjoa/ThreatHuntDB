---
id: 0e429446-2798-49e4-924d-c37338f24e23
name: Detect Certutil (LOLBins and LOLScripts) Usage
description: |
  'This detection uses Sysmon telemetry to hunt Certutil activities. Certutil is a command-line tool that is used to perform various cryptographic operations and manage ceritificates.
  It is a legitimate tool and is used by many legitimate applications. However, it is also used by malware to perform malicious activities.'
requiredDataConnectors:
  - connectorId: SecurityEvents
    dataTypes:
      - SecurityEvent
tactics:
  - CommandAndControl
relevantTechniques:
  - T1105
query: "```kusto\nEvent\n//This query uses sysmon data and depending on table name used, this may need to be updated\n| where Source =~ \"Microsoft-Windows-Sysmon\"\n| where EventID == 1\n| extend RenderedDescription = tostring(split(RenderedDescription, \":\")[0])\n| extend EventData = parse_xml(EventData).DataItem.EventData.Data\n| mv-expand bagexpansion=array EventData\n| evaluate bag_unpack(EventData)\n| extend Key = tostring(column_ifexists('@Name', \"\")), Value = column_ifexists('#text', \"\")\n| evaluate pivot(Key, any(Value), TimeGenerated, Source, EventLog, Computer, EventLevel, EventLevelName, EventID, UserName, RenderedDescription, MG, ManagementGroupName, Type, _ResourceId)\n| extend RuleName = column_ifexists(\"RuleName\", \"\"), TechniqueId = column_ifexists(\"TechniqueId\", \"\"),  TechniqueName = column_ifexists(\"TechniqueName\", \"\")\n| parse RuleName with * 'technique_id=' TechniqueId ',' * 'technique_name=' TechniqueName\n| extend Image = column_ifexists(\"Image\", \"\")\n| where Image has \"certutil.exe\"\n// Uncomment the next line and add your commandLine Whitelisted/ignore terms.For example \"urlcache\"\n// | where CommandLine !contains (\"urlcache\") \n| extend NTDomain = tostring(split(UserName, '\\\\', 0)[0]), Name = tostring(split(UserName, '\\\\', 1)[0])\n| extend HostName = tostring(split(Computer, '.', 0)[0]), DnsDomain = tostring(strcat_array(array_slice(split(Computer, '.'), 1, -1), '.'))\n| extend Account_0_Name = Name\n| extend Account_0_NTDomain = NTDomain\n| extend Host_0_HostName = HostName\n| extend Host_0_DnsDomain = DnsDomain\n```"
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

