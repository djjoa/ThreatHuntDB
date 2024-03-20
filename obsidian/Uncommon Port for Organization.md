---
id: 8812a547-13e6-4d0c-b38d-476fb7351c52
name: Uncommon Port for Organization
description: |
  'Identifies abnormal ports used in the organization based on learning period activity. This can indicate exfiltration attack or C2 control from machines in the organization by using new a port that has never been used.'
requiredDataConnectors:
  - connectorId: AzureFirewall
    dataTypes:
      - AzureDiagnostics
      - AZFWNetworkRule
      - AZFWApplicationRule
tactics:
  - Defense Evasion
  - Exfiltration
  - CommandAndControl
relevantTechniques: []
query: "```kusto\nlet LearningPeriod = 7d; \nlet RunTime = 1h; \nlet StartLearningPeriod = LearningPeriod + RunTime; \nlet EndRunTime = RunTime - 1d; \nlet AllowedCommonPorts = dynamic([80, 443]); \nlet TrafficLogs = (union isfuzzy=true\n(AzureDiagnostics\n| where OperationName == \"AzureFirewallApplicationRuleLog\" or OperationName == \"AzureFirewallNetworkRuleLog\" \n| parse msg_s with * \"from \" SourceIp \":\" SourcePort:int \" to \" Fqdn \":\" DestinationPort:int \". \" * \"Action: \" Action \".\" *\n| where isnotempty(SourceIp)),\n(AZFWApplicationRule\n| where isnotempty(Fqdn) and isnotempty(SourceIp)),\n(AZFWNetworkRule\n| extend Fqdn = DestinationIp\n| where isnotempty(Fqdn) and isnotempty(SourceIp)));\nlet LearningSrcIp = (TrafficLogs \n| where TimeGenerated between (ago(StartLearningPeriod) .. ago(RunTime)) \n| distinct DestinationPort);\nlet AlertTimeSrcIpToPort = (TrafficLogs \n| where TimeGenerated between (ago(RunTime) .. ago(EndRunTime)) \n| distinct SourceIp, DestinationPort, Fqdn);\nAlertTimeSrcIpToPort \n| join kind=leftantisemi (LearningSrcIp) on DestinationPort \n| where DestinationPort !in (AllowedCommonPorts)\n| extend IPCustomEntity = SourceIp, URLCustomEntity = Fqdn\n```"
---

