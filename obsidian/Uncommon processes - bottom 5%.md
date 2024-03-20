---
id: 2ff4b10c-7056-4898-83fd-774104189fd5
name: Uncommon processes - bottom 5%
description: |
  'Query highlights uncommon, rare process runs, to flag new potentially unauthorized binaries in stable environments for potential attack detection.'
description-detailed: "'Shows the rarest processes seen running for the first time. (Performs best over longer time ranges - eg 3+ days rather than 24 hours!)\nThese new processes could be benign new programs installed on hosts; \nHowever, especially in normally stable environments, these new processes could provide an indication of an unauthorized/malicious binary that has been installed and run. \nReviewing the wider context of the logon sessions in which these binaries ran can provide a good starting point for identifying possible attacks.'\n"
requiredDataConnectors:
  - connectorId: SecurityEvents
    dataTypes:
      - SecurityEvent
  - connectorId: WindowsSecurityEvents
    dataTypes:
      - SecurityEvent
tactics:
  - Execution
query: "```kusto\nlet ProcessCreationEvents=() {\nlet processEvents=SecurityEvent\n| where EventID==4688\n// filter out common randomly named files related to MSI installers and browsers\n| where not(NewProcessName matches regex @\"\\\\TRA[0-9A-Fa-f]{3}\\.tmp\")\n| where not(NewProcessName matches regex @\"\\\\TRA[0-9A-Fa-f]{4}\\.tmp\")\n| where not(NewProcessName matches regex @\"Installer\\\\MSI[0-9A-Fa-f]{3}\\.tmp\")\n| where not(NewProcessName matches regex @\"Installer\\\\MSI[0-9A-Fa-f]{4}\\.tmp\")\n| project TimeGenerated, ComputerName=Computer, AccountName=SubjectUserName, AccountDomain=SubjectDomainName,\nFileName=tostring(split(NewProcessName, '\\\\')[-1]), ProcessCommandLine = CommandLine, \nInitiatingProcessFileName=ParentProcessName, InitiatingProcessCommandLine=\"\", InitiatingProcessParentFileName=\"\";\nprocessEvents;\n};\nlet normalizedProcesses = ProcessCreationEvents \n// normalize guids\n| project TimeGenerated, FileName = replace(\"[0-9A-Fa-f]{8}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{12}\", \"<guid>\", FileName)\n// normalize digits away\n| project TimeGenerated, FileName=replace(@'\\d', 'n', FileName); \nlet freqs = normalizedProcesses\n| summarize frequency=count() by FileName\n| join kind= leftouter (\nnormalizedProcesses\n| summarize Since=min(TimeGenerated), LastSeen=max(TimeGenerated) by FileName\n) on FileName;\nfreqs \n| where frequency <= toscalar( freqs | serialize | project frequency | summarize percentiles(frequency, 5))\n| order by frequency asc\n| project FileName, frequency, Since, LastSeen \n// restrict results to unusual processes seen in last day \n| where LastSeen >= ago(1d)\n| extend timestamp = LastSeen \n| extend File_0_Name = FileName\n```"
entityMappings:
  - entityType: File
    fieldMappings:
      - identifier: Name
        columnName: FileName
version: 2.0.2
---

