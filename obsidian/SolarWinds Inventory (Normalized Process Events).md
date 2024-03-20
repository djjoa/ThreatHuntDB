---
id: c3f1606e-48eb-464e-a60c-d53af5a5796e
name: SolarWinds Inventory (Normalized Process Events)
description: |
  'Beyond your internal software management systems, it is possible you may not have visibility into your entire footprint of SolarWinds installations.  This is intended to help use process exection information to discovery any systems that have SolarWinds processes'
requiredDataConnectors: []
tactics:
  - Execution
relevantTechniques:
  - T1072
tags:
  - Solorigate
  - NOBELIUM
query: "```kusto\nimProcessCreate\n| where Process has 'solarwinds' \n| extend MachineName = DvcHostname , Process = TargetProcessName\n| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), MachineCount = dcount(Dvc), AccountCount = dcount(User), MachineNames = make_set(Dvc, 200),\nAccounts = make_set(User, 200) by Process, EventVendor, EventProduct\n```"
version: 1.0.0
---

