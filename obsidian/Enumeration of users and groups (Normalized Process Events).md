---
id: 7b3ed03a-7474-4dad-9c6a-92e7b69f6584
name: Enumeration of users and groups (Normalized Process Events)
description: |
  'Finds attempts to list users or groups using the built-in Windows 'net' tool '
requiredDataConnectors: []
tactics:
  - Discovery
query: "```kusto\n\nimProcessCreate\n| where (CommandLine has ' user ' or CommandLine has ' group ') and (CommandLine hassuffix ' /do' or CommandLine hassuffix ' /domain') \n| where Process has 'net.exe' // performance pre-filtering\n| extend FileName=tostring(split(Process, '\\\\')[-1])\n| where FileName == 'net.exe' and ActorUsername != \"\" and CommandLine !contains '\\\\'  and CommandLine !contains '/add' \n| extend Target = extract(\"(?i)[user|group] (\\\"*[a-zA-Z0-9-_ ]+\\\"*)\", 1, CommandLine) \n| where Target  != '' \n| summarize minTimeGenerated=min(TimeGenerated), maxTimeGenerated=max(TimeGenerated), count() by ActorUsername, Target, CommandLine, Dvc, EventVendor, EventProduct\n| sort by ActorUsername, Target\n| extend timestamp = minTimeGenerated, AccountCustomEntity = ActorUsername, HostCustomEntity = Dvc\n```"
---

