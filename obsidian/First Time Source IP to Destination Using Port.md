---
id: 932fe71a-7a8c-4f35-bf88-321ab68ff562
name: First Time Source IP to Destination Using Port
description: "'Identifies the first time a source IP communicates with a destination using a specific port based on learning period activity. \nConfigurable Parameters: - Learning period time - learning period for threshold calculation in days. Default is set to 7.'\n"
requiredDataConnectors:
  - connectorId: AzureFirewall
    dataTypes:
      - AzureDiagnostics
      - AZFWApplicationRule
      - AZFWNetworkRule
tactics:
  - Exfiltration
  - CommandAndControl
relevantTechniques: []
query: |-
  ```kusto
  let LearningPeriod = 7d;
  let RunTime = 1h;
  let StartLearningPeriod = LearningPeriod + RunTime;
  let EndRunTime = RunTime - 1d;
  let TrafficLogs = (union isfuzzy=true
  (AzureDiagnostics
    | where OperationName == "AzureFirewallApplicationRuleLog" or OperationName == "AzureFirewallNetworkRuleLog"
    | parse msg_s with * "from " SourceIp ":" SourcePort:int " to " Fqdn ":" DestinationPort:int "." *
    | where isnotempty(Fqdn) and isnotempty(SourceIp)),
  (AZFWApplicationRule),
  (AZFWNetworkRule
  | extend Fqdn = DestinationIp));
  let LearningSrcIpToDstIpPort = (TrafficLogs
  | where TimeGenerated between (ago(StartLearningPeriod) .. ago(RunTime))
  | summarize LearningSrcToDsts = make_set(Fqdn,10000) by SourceIp, DestinationPort);
  let AlertTimeSrcIpToDstIpPort = (TrafficLogs
  | where TimeGenerated between (ago(RunTime) .. ago(EndRunTime))
  | extend AlertTimeDst = Fqdn
  | distinct AlertTimeDst ,SourceIp, DestinationPort);
  AlertTimeSrcIpToDstIpPort
  | join kind=leftouter (LearningSrcIpToDstIpPort) on SourceIp, DestinationPort
  | mv-expand LearningSrcToDsts
  | where AlertTimeDst != LearningSrcToDsts
  | summarize LearningSrcToDsts = make_set(LearningSrcToDsts,10000) by SourceIp, AlertTimeDst, DestinationPort
  ```
---
