---
id: 4a5e9079-8fca-451a-99f5-a3384755a6e8
name: Most Common Services
description: |
  This query provides the most common services discovered
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceTvmSoftwareVulnerabilities
tactics:
  - Initial Access
  - Execution
relevantTechniques: []
query: "```kusto\n//\nDeviceTvmSoftwareVulnerabilities \n| where ingestion_time() > ago(7d)\n| summarize arg_max(DeviceId, *) by SoftwareVendor, SoftwareName\n| summarize DiscoveredOnDevicesCount = dcount(DeviceId) by SoftwareVendor, SoftwareName\n```"
---

