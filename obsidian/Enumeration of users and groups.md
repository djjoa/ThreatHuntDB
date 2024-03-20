---
id: a1e993de-770a-4434-83e9-9e3b47a6e470
name: Enumeration of users and groups
description: |
  'Finds attempts to list users or groups using the built-in Windows 'net' tool '
requiredDataConnectors:
  - connectorId: SecurityEvents
    dataTypes:
      - SecurityEvent
  - connectorId: WindowsSecurityEvents
    dataTypes:
      - SecurityEvent
tactics:
  - Discovery
query: "```kusto\nlet ProcessCreationEvents=() {\nlet processEvents=SecurityEvent\n| where EventID==4688\n| project TimeGenerated, ComputerName=Computer,AccountName=SubjectUserName,AccountDomain=SubjectDomainName,\nFileName=tostring(split(NewProcessName, '\\\\')[-1]),\nProcessCommandLine = CommandLine, \nFolderPath = \"\",\nInitiatingProcessFileName=ParentProcessName,InitiatingProcessCommandLine=\"\",InitiatingProcessParentFileName=\"\";\nprocessEvents};\nProcessCreationEvents\n| where FileName == 'net.exe' and AccountName != \"\" and ProcessCommandLine !contains '\\\\'  and ProcessCommandLine !contains '/add' \n| where (ProcessCommandLine contains ' user ' or ProcessCommandLine contains ' group ') and (ProcessCommandLine endswith ' /do' or ProcessCommandLine endswith ' /domain') \n| extend Target = extract(\"(?i)[user|group] (\\\"*[a-zA-Z0-9-_ ]+\\\"*)\", 1, ProcessCommandLine) | filter Target  != '' \n| summarize minTimeGenerated=min(TimeGenerated), maxTimeGenerated=max(TimeGenerated), count() by AccountName, Target, ProcessCommandLine, ComputerName\n| project minTimeGenerated, maxTimeGenerated, count_, AccountName, Target, ProcessCommandLine, ComputerName\n| sort by AccountName, Target\n| extend HostName = tostring(split(ComputerName, '.', 0)[0]), DnsDomain = tostring(strcat_array(array_slice(split(ComputerName, '.'), 1, -1), '.'))\n| extend Account_0_Name = AccountName\n| extend Host_0_HostName = HostName\n| extend Host_0_DnsDomain = DnsDomain\n```"
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

