---
id: 36abe031-962d-482e-8e1e-a556ed99d5a3
name: Cscript script daily summary breakdown
description: |
  'breakdown of scripts running in the environment'
requiredDataConnectors:
  - connectorId: SecurityEvents
    dataTypes:
      - SecurityEvent
  - connectorId: WindowsSecurityEvents
    dataTypes:
      - SecurityEvent
tactics:
  - Execution
query: "```kusto\nlet ProcessCreationEvents=() {\nlet processEvents=SecurityEvent\n| where EventID==4688\n| project EventTime=TimeGenerated, ComputerName=Computer,AccountName=SubjectUserName, AccountDomain=SubjectDomainName,\nFileName=tostring(split(NewProcessName, '\\\\')[-1]),  ProcessCommandLine = CommandLine, \nInitiatingProcessFileName=ParentProcessName,InitiatingProcessCommandLine=\"\",InitiatingProcessParentFileName=\"\";\nprocessEvents;\n};\n// Daily summary of cscript activity - extracting script name and parameters from commandline:\nProcessCreationEvents \n| where FileName =~ \"cscript.exe\"\n// remove commandline switches\n| project EventTime, ComputerName, AccountName, removeSwitches = replace(@\"/+[a-zA-Z0-9:]+\", \"\", ProcessCommandLine)\n// remove the leading cscript.exe process name \n| project EventTime, ComputerName, AccountName, CommandLine = trim(@\"[a-zA-Z0-9\\\\:\"\"]*cscript(.exe)?(\"\")?(\\s)+\", removeSwitches)\n// extract the script name:\n| project EventTime, ComputerName, AccountName, \n// handle case where script name is enclosed in \" characters or is not enclosed in quotes \nScriptName= iff(CommandLine startswith @\"\"\"\", \nextract(@\"([:\\\\a-zA-Z_\\-\\s0-9\\.()]+)(\"\"?)\", 0, CommandLine), \nextract(@\"([:\\\\a-zA-Z_\\-0-9\\.()]+)(\"\"?)\", 0, CommandLine)), CommandLine \n| project EventTime, ComputerName, AccountName, ScriptName=trim(@\"\"\"\", ScriptName) , ScriptNameLength=strlen(ScriptName), CommandLine \n// extract remainder of commandline as script parameters: \n| project EventTime, ComputerName, AccountName, ScriptName, ScriptParams = iff(ScriptNameLength < strlen(CommandLine), substring(CommandLine, ScriptNameLength +1), \"\")\n| summarize min(EventTime), count() by ComputerName, AccountName, ScriptName, ScriptParams\n| order by count_ asc nulls last\n| extend HostName = tostring(split(ComputerName, '.', 0)[0]), DnsDomain = tostring(strcat_array(array_slice(split(ComputerName, '.'), 1, -1), '.'))\n| extend Account_0_Name = AccountName\n| extend Host_0_HostName = HostName\n| extend Host_0_DnsDomain = DnsDomain\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountName
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostName
      - identifier: DnsDomain
        columnName: DnsDomain
version: 2.0.1
---

