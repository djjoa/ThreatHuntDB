---
id: af02987c-949d-47d5-b0ae-64d8e1b674e2
name: Rare Processes Run by Service Accounts
description: |
  'Service accounts normally are supposed to perform a limited set of tasks in a stable environment.
  The query collects a list of service account and then joins them with rare processes in an environment to detect anomalous behaviours.'
requiredDataConnectors:
  - connectorId: SecurityEvents
    dataTypes:
      - SecurityEvent
  - connectorId: WindowsSecurityEvents
    dataTypes:
      - SecurityEvent
tactics:
  - Execution
query: "```kusto\nlet starttime = todatetime('{{StartTimeISO}}');\nlet endtime = todatetime('{{EndTimeISO}}');\n// Configure common/frequent processes for exclusion \nlet excludeList = dynamic ( [\"NT AUTHORITY\",\"Local System\", \"Local Service\", \"Network Service\"] );\n// Provide a list of service account/ built-in accounts in an environment.\nlet List1 = datatable(AccountName:string)[\"MSSQLSERVER\", \"ReportServer\", \"MSDTSServer100\", \"IUSR\"];\n// Self generating a list of Service account using event Id :4624\nlet List2 = SecurityEvent\n| where TimeGenerated between(starttime..endtime)\n| where EventID == 4624\n| where LogonType == \"5\"\n| where not(Account has_any (excludeList))\n| extend AccountName = Account\n| distinct AccountName;\nlet Accounts = List1 | union (List2 | distinct AccountName);\nlet ProcessCreationEvents=() {\n    let processEvents=SecurityEvent\n\t  | where TimeGenerated between(starttime..endtime)\n    | where EventID==4688\n    // filter out common randomly named files related to MSI installers and browsers\n    | where not(NewProcessName matches regex @\"\\\\TRA[0-9A-Fa-f]{3}\\.tmp\")\n    | where not(NewProcessName matches regex @\"\\\\TRA[0-9A-Fa-f]{4}\\.tmp\")\n    | where not(NewProcessName matches regex @\"Installer\\\\MSI[0-9A-Fa-f]{3}\\.tmp\")\n    | where not(NewProcessName matches regex @\"Installer\\\\MSI[0-9A-Fa-f]{4}\\.tmp\")\n    | project TimeGenerated,\n      ComputerName=Computer,\n      AccountName=Account,\n      AccountDomain=SubjectDomainName,\n      FileName=tostring(split(NewProcessName, '\\\\')[-1]),\n      ProcessCommandLine = CommandLine,\n      InitiatingProcessFileName=ParentProcessName,\n      InitiatingProcessCommandLine=\"\",\n      InitiatingProcessParentFileName=\"\";\n    processEvents;\n    };\n    let normalizedProcesses = ProcessCreationEvents\n       // normalize guids\n       | project TimeGenerated, AccountName, FileName = replace(\"[0-9A-Fa-f]{8}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{12}\", \"<guid>\", FileName)\n       // normalize digits away\n       | project TimeGenerated, AccountName, FileName=replace(@'\\d', 'n', FileName);\nlet freqs = normalizedProcesses\n    | summarize frequency = count() by FileName\n    | join kind= leftouter (\n       normalizedProcesses\n       | summarize Since=min(TimeGenerated), LastSeen=max(TimeGenerated)  by FileName, AccountName\n    ) on FileName;\n   let Finalfreqs = freqs\n    | where frequency <= toscalar( freqs | serialize | project frequency | summarize percentiles(frequency, 10))\n    | order by frequency asc\n    | project FileName, frequency, Since, LastSeen , AccountName\n    // restrict results to unusual processes seen in last day\n    | where LastSeen between(starttime..endtime);\nAccounts\n    | join kind= inner (\n        Finalfreqs\n) on AccountName\n| where frequency < 10\n| project-away AccountName1\n| extend NTDomain = split(AccountName, '\\\\', 0)[0], Name = split(AccountName, '\\\\', 1)[0]\n| extend Account_0_Name = Name\n| extend Account_0_NTDomain = NTDomain\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: Name
      - identifier: NTDomain
        columnName: NTDomain
version: 1.0.1
---

