---
id: 33aa0e01-87e2-43ea-87f9-2f7e3ff1d532
name: Detect beacon like pattern based on repetitive time intervals in Wire Data Traffic
description: |
  'Query identifies beaconing patterns from Wire Data logs. Uses KQL functions to calculate time delta and find beaconing percentage. Results of beaconing to untrusted public networks can be investigated.'
description_detailed: |
  'This query will identify beaconing patterns from Wire Data logs based on timedelta patterns. The query leverages various KQL functions
  to calculate time delta and then compare it with total events observed in a day to find percentage of beaconing.
  Results of such beaconing patterns to untrusted public networks can be a good starting point for investigation.
  References: Blog about creating dataset to identify network beaconing via repetitive time intervals seen against total traffic
  between same source-destination pair.
  http://www.austintaylor.io/detect/beaconing/intrusion/detection/system/command/control/flare/elastic/stack/2017/06/10/detect-beaconing-with-flare-elasticsearch-and-intrusion-detection-systems/'
requiredDataConnectors:
  - connectorId: AzureMonitor(WireData)
    dataTypes:
      - WireData
tactics:
  - CommandAndControl
relevantTechniques:
  - T1071
  - T1571
query: |-
  ```kusto

  let lookback = 1d;
  let TimeDeltaThreshold = 10;
  let TotalEventsThreshold = 15;
  let PercentBeaconThreshold = 95;
  WireData
  | where TimeGenerated > ago(lookback)
  | where ipv4_is_private(RemoteIP) == false
  | project TimeGenerated , LocalIP , LocalPortNumber , RemoteIP, RemotePortNumber, ReceivedBytes, SentBytes
  | sort by LocalIP asc,TimeGenerated asc, RemoteIP asc, RemotePortNumber asc
  | serialize
  | extend nextTimeGenerated = next(TimeGenerated, 1), nextLocalIP = next(LocalIP, 1)
  | extend TimeDeltainSeconds = datetime_diff('second',nextTimeGenerated,TimeGenerated)
  | where LocalIP == nextLocalIP
  //Whitelisting criteria/ threshold criteria
  | where TimeDeltainSeconds > TimeDeltaThreshold
  | where RemotePortNumber != "0"
  | project TimeGenerated, TimeDeltainSeconds, LocalIP, LocalPortNumber,RemoteIP,RemotePortNumber, ReceivedBytes, SentBytes
  | summarize count(), sum(ReceivedBytes), sum(SentBytes), make_list(TimeDeltainSeconds) by TimeDeltainSeconds, bin(TimeGenerated, 1h), LocalIP, RemoteIP, RemotePortNumber
  | summarize (MostFrequentTimeDeltaCount, MostFrequentTimeDeltainSeconds)=arg_max(count_, TimeDeltainSeconds), TotalEvents=sum(count_), TotalSentBytes=sum(sum_SentBytes),TotalReceivedBytes=sum(sum_ReceivedBytes) by bin(TimeGenerated, 1h), LocalIP, RemoteIP, RemotePortNumber
  | where TotalEvents > TotalEventsThreshold
  | extend BeaconPercent = MostFrequentTimeDeltaCount/toreal(TotalEvents) * 100
  | where BeaconPercent > PercentBeaconThreshold
  | extend timestamp = TimeGenerated, IPCustomEntity = RemoteIP
  ```
version: 1.0.2
metadata:
  source:
    kind: Community
  author:
    name: Shain
  support:
    tier: Community
  categories:
    domains: ["Security - Other"]
---

