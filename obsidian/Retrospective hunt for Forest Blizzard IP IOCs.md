---
id: b8b7574f-1cd6-4308-822a-ab07256106f8
name: Retrospective hunt for Forest Blizzard IP IOCs
description: |
  'Matches domain name IOCs related to Forest Blizzard group activity with CommonSecurityLog and SecurityAlert dataTypes.
  The query is scoped in the time window that these IOCs were active.'
description-detailed: |
  'Matches domain name IOCs related to Forest Blizzard group activity with CommonSecurityLog and SecurityAlert dataTypes.
  The query is scoped in the time window that these IOCs were active.
  References: https://blogs.microsoft.com/on-the-issues/2019/07/17/new-cyberthreats-require-new-ways-to-protect-democracy.'
severity: High
requiredDataConnectors:
  - connectorId: CiscoASA
    dataTypes:
      - CommonSecurityLog
  - connectorId: PaloAltoNetworks
    dataTypes:
      - CommonSecurityLog
  - connectorId: AzureSecurityCenter
    dataTypes:
      - SecurityAlert
tactics:
  - CommandAndControl
relevantTechniques:
  - T1071
query: "```kusto\n\nlet STRONTIUM_IPS = dynamic([\"82.118.242.171\" , \"167.114.153.55\" , \"94.237.37.28\", \"31.220.61.251\" , \"128.199.199.187\" ]);\n(union isfuzzy=true\n(CommonSecurityLog\n| where TimeGenerated between (startofday(datetime(2019-02-01)) .. endofday(datetime(2019-08-05)))\n| where SourceIP in (STRONTIUM_IPS) or DestinationIP in (STRONTIUM_IPS)\n| extend IPCustomEntity = SourceIP\n),\n(SecurityAlert\n| where TimeGenerated between (startofday(datetime(2019-02-01)) .. endofday(datetime(2019-08-05)))\n| extend RemoteAddress = iff(ExtendedProperties has \"RemoteAddress\", tostring(parse_json(ExtendedProperties)[\"RemoteAddress\"]), \"None\")\n| where RemoteAddress != \"None\"\n| where RemoteAddress in (STRONTIUM_IPS)\n| extend IPCustomEntity = RemoteAddress\n) \n)\n| extend timestamp = TimeGenerated\n```"
version: 1.0.2
---

