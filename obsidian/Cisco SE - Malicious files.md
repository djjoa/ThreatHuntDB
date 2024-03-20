---
id: d074fc1b-e276-48c8-9ef4-d691652a6625
name: Cisco SE - Malicious files
description: |
  'Query searches for malicious files.'
severity: High
requiredDataConnectors:
  - connectorId: CiscoSecureEndpoint
    dataTypes:
      - CiscoSecureEndpoint
tactics:
  - Execution
relevantTechniques:
  - T1204.002
query: |-
  ```kusto
  CiscoSecureEndpoint
  | where TimeGenerated > ago(24h)
  | where IndicatorThreatType =~ 'Malicious'
  | order by TimeGenerated desc
  | extend FileCustomEntity = SrcFileName, HostCustomEntity = DstHostname
  ```
entityMappings:
  - entityType: File
    fieldMappings:
      - identifier: Name
        columnName: FileCustomEntity
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostCustomEntity
---
