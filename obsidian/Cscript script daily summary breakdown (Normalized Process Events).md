---
id: bd89c7a0-76cb-4fa1-bc64-c366687cda9e
name: Cscript script daily summary breakdown (Normalized Process Events)
description: |
  'breakdown of scripts running in the environment'
requiredDataConnectors: []
tactics:
  - Execution
query: "```kusto\nimProcessCreate\n| where Process has \"cscript.exe\"\n| extend FileName=tostring(split(Process, '\\\\')[-1])\n| where FileName =~ \"cscript.exe\"\n| extend removeSwitches = replace(@\"/+[a-zA-Z0-9:]+\", \"\", CommandLine)\n| extend CommandLine = trim(@\"[a-zA-Z0-9\\\\:\"\"]*cscript(.exe)?(\"\")?(\\s)+\", removeSwitches)\n// handle case where script name is enclosed in \" characters or is not enclosed in quotes \n| extend ScriptName= iff(CommandLine startswith @\"\"\"\", \nextract(@\"([:\\\\a-zA-Z_\\-\\s0-9\\.()]+)(\"\"?)\", 0, CommandLine), \nextract(@\"([:\\\\a-zA-Z_\\-0-9\\.()]+)(\"\"?)\", 0, CommandLine))\n| extend ScriptName=trim(@\"\"\"\", ScriptName) , ScriptNameLength=strlen(ScriptName)\n// extract remainder of commandline as script parameters: \n| extend ScriptParams = iff(ScriptNameLength < strlen(CommandLine), substring(CommandLine, ScriptNameLength +1), \"\")\n| summarize min(TimeGenerated), count() by Dvc, User, ScriptName, ScriptParams, EventVendor, EventProduct\n| order by count_ asc nulls last \n| extend timestamp = min_TimeGenerated, HostCustomEntity = Dvc, AccountCustomEntity = User\n```"
---

