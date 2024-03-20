---
id: d69f0373-f424-4f17-a34a-8379974fec6e
name: VMware ESXi - List of unused VMs
description: |
  'Query searches for unused VMs.'
severity: Low
requiredDataConnectors:
  - connectorId: VMwareESXi
    dataTypes:
      - VMwareESXi
tactics:
  - InitialAccess
relevantTechniques:
  - T1190
query: "```kusto\nlet vm_p_off =\nVMwareESXi\n| where TimeGenerated > ago(30d)\n| where SyslogMessage has ('VmPoweredOffEvent')\n| extend DstHostname = extract(@'\\[\\d+\\]\\s+\\[(.*?)\\s+on', 1, SyslogMessage)\n| summarize LastPowerOffTime=max(TimeGenerated) by DstHostname\n| where datetime_diff('day', datetime(now), LastPowerOffTime) >= 20; \nlet vm_p_on =\nVMwareESXi\n| where TimeGenerated > ago(30d)\n| where SyslogMessage has ('VmPoweredOnEvent')\n| extend DstHostname = extract(@'\\[\\d+\\]\\s+\\[(.*?)\\s+on', 1, SyslogMessage)\n| summarize LastPowerOnTime=max(TimeGenerated) by DstHostname\n| where datetime_diff('day',datetime(now),LastPowerOnTime) >= 20;\nlet off_vms =\nvm_p_on\n| join (vm_p_off) on DstHostname\n| where LastPowerOffTime > LastPowerOnTime\n| summarize p_off_vm = makeset(DstHostname)\n| extend k=1;\nlet p_on_vms =\nVMwareESXi\n| where TimeGenerated between (ago(24h) .. datetime(now))\n| where SyslogMessage has ('VmPoweredOnEvent')\n| extend DstHostname = extract(@'\\[\\d+\\]\\s+\\[(.*?)\\s+on', 1, SyslogMessage)\n| extend k=1\n| join (off_vms) on k\n| where p_off_vm !has DstHostname\n| summarize rec_p_on = makeset(DstHostname)\n| extend k=1;\nVMwareESXi\n| where TimeGenerated between (ago(24h) .. datetime(now))\n| where SyslogMessage has ('VmPoweredOnEvent')\n| extend DstHostname = extract(@'\\[\\d+\\]\\s+\\[(.*?)\\s+on', 1, SyslogMessage)\n| extend k=1\n| join (p_on_vms) on k\n| where  rec_p_on !has DstHostname\n| extend HostCustomEntity = DstHostname\n```"
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: FullName
        columnName: HostCustomEntity
---

