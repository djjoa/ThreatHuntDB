---
id: 148de00b-e647-4767-9201-c3cbf51befb1
name: MailItemsAccessedTimeSeries[Solarigate]
description: |
  Identifies anomalous increases in Exchange mail items accessed operations.
  The query leverages KQL built-in anomaly detection algorithms to find large deviations from baseline patterns.
  Sudden increases in execution frequency of sensitive actions should be further investigated for malicious activity.
  Manually change scorethreshold from 1.5 to 3 or higher to reduce the noise based on outliers flagged from the query criteria.
  Read more about MailItemsAccessed- https://docs.microsoft.com/microsoft-365/compliance/advanced-audit?view=o365-worldwide#mailitemsaccessed
  Query insprired by Azure Sentinel detection https://github.com/Azure/Azure-Sentinel/blob/master/Detections/OfficeActivity/MailItemsAccessedTimeSeries.yaml
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - CloudAppEvents
tactics:
  - Collection
query: "```kusto\nlet starttime = 14d;\nlet endtime = 1d;\nlet timeframe = 1h;\nlet scorethreshold = 1.5;\nlet percentthreshold = 50;\n// Preparing the time series data aggregated hourly count of MailItemsAccessd Operation in the form of multi-value array to use with time series anomaly function.\nlet TimeSeriesData =\n    CloudAppEvents \n    | where Timestamp   between (startofday(ago(starttime))..startofday(ago(endtime)))\n    | where ActionType =~ \"MailItemsAccessed\"\n    | where Application has \"Exchange\"\n    | extend RawEventData = parse_json(RawEventData)\n    | where RawEventData.ResultStatus == \"Succeeded\"  \n    | project Timestamp, ActionType, RawEventData.MailboxOwnerUPN    \n    | make-series Total=count() on Timestamp from startofday(ago(starttime)) to startofday(ago(endtime)) step timeframe;\nlet TimeSeriesAlerts =\n  TimeSeriesData\n  | extend (anomalies, score, baseline) = series_decompose_anomalies(Total, scorethreshold, -1, 'linefit')\n  | mv-expand Total to typeof(double), Timestamp to typeof(datetime), anomalies to typeof(double), score to typeof(double), baseline to typeof(long)\n  | where anomalies > 0\n  | project Timestamp, Total, baseline, anomalies, score;\n  // Joining the flagged outlier from the previous step with the original dataset to present contextual information\n  // during the anomalyhour to analysts to conduct investigation or informed decisions.\n  TimeSeriesAlerts | where Timestamp > ago(2d)  \n  // Join against base logs since specified timeframe to retrive records associated with the hour of anomoly\n  | join (\n      CloudAppEvents \n        | where Timestamp > ago(2d)\n        | where ActionType =~ \"MailItemsAccessed\"\n        | where Application has \"Exchange\"\n        | extend RawEventData = parse_json(RawEventData)\n        | where RawEventData.ResultStatus == \"Succeeded\"  \n  ) on Timestamp\n```"
---

