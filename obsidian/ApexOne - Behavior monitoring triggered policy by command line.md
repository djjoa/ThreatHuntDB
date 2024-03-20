---
id: 14a4a824-67b6-11ec-90d6-0242ac120003
name: ApexOne - Behavior monitoring triggered policy by command line
description: |
  'Shows behavior monitoring triggered policy by command line.'
severity: Medium
requiredDataConnectors:
  - connectorId: TrendMicroApexOne
    dataTypes:
      - TMApexOneEvent
  - connectorId: TrendMicroApexOneAma
    dataTypes:
      - TMApexOneEvent
tactics:
  - Execution
relevantTechniques:
  - T1204
query: "```kusto\nTMApexOneEvent\n| where TimeGenerated > ago(24h)\n| where EventMessage has \"Behavior Monitoring\"\n| where isnotempty(Policy)\n| extend TriggeredPolicy = case(\nPolicy == \"0\", \"Compromised executable file\", \nPolicy == \"1\", \"New startup program\",\nPolicy == \"2\", \"Host file modification\",\nPolicy == \"3\", \"Program library injection\", \nPolicy == \"4\", \"New Internet Explorer plugin\",\nPolicy == \"5\", \"Internet Explorer setting modification\",\nPolicy == \"6\", \"Shell modification\", \nPolicy == \"7\", \"New service\",\nPolicy == \"8\", \"Security policy modification\",\nPolicy == \"9\", \"Firewall policy modification\", \nPolicy == \"10\", \"System file modification\",\nPolicy == \"11\", \"Duplicated system file\",\nPolicy == \"13\", \"Layered service provider\", \nPolicy == \"14\", \"System process modification\",\nPolicy == \"16\", \"Suspicious behavior\",\nPolicy == \"100\", \"Newly encountered programs\", \nPolicy == \"200\", \"Unauthorized file encryption\",\nPolicy == \"1000\", \"Threat behavior analysis\",\nPolicy == \"9999\", \"User-defined policy\",\n\"unknown\")\n| summarize PolicyCount = count() by TriggeredPolicy, ProcessCommandLine\n| extend ProcessCustomEntity = ProcessCommandLine\n```"
entityMappings:
  - entityType: Process
    fieldMappings:
      - identifier: CommandLine
        columnName: ProcessCustomEntity
---

