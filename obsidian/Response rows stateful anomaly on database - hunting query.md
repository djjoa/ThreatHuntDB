---
id: 137tyi7c-7225-434b-8bfc-fea28v95ebd8
name: Response rows stateful anomaly on database - hunting query
description: |
  'Goal: To detect anomalous data exfiltration. This query detects SQL queries that accessed a large number of rows, which is significantly higher than normal for this database. This is a hunting query, so the training and the detection occur on the whole time window (controlled by 'queryPeriod' parameter). The user can set the minimal threshold for anomaly by changing the threshold parameters volThresholdZ and volThresholdQ (higher thresholds will detect only more severe anomalies).'
severity: Medium
requiredDataConnectors:
  - connectorId: AzureSql
    dataTypes:
      - AzureDiagnostics
queryFrequency: 1h
queryPeriod: 15d
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Exfiltration
relevantTechniques:
  - T1537
  - T1567
tags:
  - SQL
query: "```kusto\nlet volumeThresholdZ = 3.0;                     // Minimal threshold for the Zscore to trigger anomaly (number of standard deviations above mean). If set higher, only very significant alerts will fire.\nlet volumeThresholdQ = volumeThresholdZ;        // Minimal threshold for the Qscore to trigger anomaly (number of Inter-Percentile Ranges above high percentile). If set higher, only very significant alerts will fire.\nlet volumeThresholdHardcoded = 500;             // Minimal value for the volume metric to trigger anomaly.\nlet monitoredColumn = 'ResponseRows';           // The name of the column for volumetric anomalies.\nlet processedData = materialize (\n    AzureDiagnostics\n    | where Category == 'SQLSecurityAuditEvents' and action_id_s has_any (\"RCM\", \"BCM\") // Keep only SQL affected rows\n    | project TimeGenerated, PrincipalName = server_principal_name_s, ClientIp = client_ip_s, HostName = host_name_s, ResourceId,\n              ApplicationName = application_name_s, ActionName = action_name_s, Database = strcat(LogicalServerName_s, '/', database_name_s),\n              IsSuccess = succeeded_s, AffectedRows = affected_rows_d,\n              ResponseRows = response_rows_d, Statement = statement_s, \n              Error = case( additional_information_s has 'error_code', toint(extract(\"<error_code>([0-9.]+)\", 1, additional_information_s))\n                    , additional_information_s has 'failure_reason', toint(extract(\"<failure_reason>Err ([0-9.]+)\", 1, additional_information_s))\n                    , 0),\n              State = case( additional_information_s has 'error_state', toint(extract(\"<error_state>([0-9.]+)\", 1, additional_information_s))\n                    , additional_information_s has 'failure_reason', toint(extract(\"<failure_reason>Err ([0-9.]+), Level ([0-9.]+)\", 2, additional_information_s))\n                    , 0)\n    | extend QuantityColumn = column_ifexists(monitoredColumn, 0)\n    | sort by TimeGenerated desc\n    | extend RowNumber = row_number()\n    );\nlet trainingSet =\n    processedData\n    | summarize AvgVal = round(avg(QuantityColumn), 2), StdVal = round(stdev(QuantityColumn), 2), N = max(RowNumber),\n                P99Val = round(percentile(QuantityColumn, 99), 2), P50Val = round(percentile(QuantityColumn, 50), 2)\n      by Database;\nprocessedData\n| join kind = inner (trainingSet) on Database\n| extend ZScoreVal = iff(N >= 20, round(todouble(QuantityColumn - AvgVal) / todouble(StdVal + 1), 2), 0.00),\n         QScoreVal = iff(N >= 20, round(todouble(QuantityColumn - P99Val) / todouble(P99Val - P50Val + 1), 2), 0.00)\n| extend IsVolumeAnomalyOnVal = iff((ZScoreVal > volumeThresholdZ and QScoreVal > volumeThresholdQ and QuantityColumn > volumeThresholdHardcoded), true, false), AnomalyScore = round((ZScoreVal + QScoreVal)/2, 0)\n| project TimeGenerated, Database, PrincipalName, ClientIp, HostName, ApplicationName, ActionName, Statement,\n          IsSuccess, ResponseRows, AffectedRows, IsVolumeAnomalyOnVal, AnomalyScore\n| where IsVolumeAnomalyOnVal == 'true'\n| sort by AnomalyScore desc, TimeGenerated desc\n| extend Name = tostring(split(PrincipalName, '@', 0)[0]), UPNSuffix = tostring(split(PrincipalName, '@', 1)[0])\n| extend Account_0_Name = Name\n| extend Account_0_UPNSuffix = UPNSuffix\n| extend IP_0_Address = ClientIp\n| extend Host_0_Hostname = HostName\n| extend CloudApplication_0_Name = ApplicationName\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: Name
      - identifier: UPNSuffix
        columnName: UPNSuffix
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: ClientIp
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostName
  - entityType: CloudApplication
    fieldMappings:
      - identifier: Name
        columnName: ApplicationName
version: 1.0.1
---

