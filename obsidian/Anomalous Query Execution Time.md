---
id: af55d5b0-6b4a-4874-8299-9d845bf7c1fd
name: Anomalous Query Execution Time
description: |
  'This hunting query will detect SQL queries that took an unusually long period of time to execute based on a calculated average execution time. The query groups based on the application and the username, making this query suitable for detecting exploitation of web applications, or other SQL backed applications with predictable behaviour.'
requiredDataConnectors:
  - connectorId: AzureSql
    dataTypes:
      - AzureDiagnostics
tactics:
  - InitialAccess
relevantTechniques:
  - T1190
tags:
  - SQL
query: "```kusto\nlet timeRange = 14d;\n//How frequently the query averages data for an average execution time\nlet timeSliceSize = 1h;\n//Anomaly decompose threshold, 2 by default\nlet scoreThreshold = 2;\nlet processedData = materialize (\n    AzureDiagnostics\n    | where TimeGenerated > ago(timeRange)\n    | where Category == 'SQLSecurityAuditEvents' and action_id_s has_any (\"RCM\", \"BCM\") // Keep only SQL affected rows\n    | project TimeGenerated, PrincipalName = server_principal_name_s, ClientIp = client_ip_s, HostName = host_name_s, ResourceId,\n    ApplicationName = application_name_s, ActionName = action_name_s, Database = strcat(LogicalServerName_s, '/', database_name_s),\n    IsSuccess = succeeded_s, DurationMs = duration_milliseconds_d, AffectedRows = affected_rows_d,\n    ResponseRows = response_rows_d, Statement = statement_s,\n    Error = case( additional_information_s has 'error_code', toint(extract(\"<error_code>([0-9.]+)\", 1, additional_information_s))\n                      , additional_information_s has 'failure_reason', toint(extract(\"<failure_reason>Err ([0-9.]+)\", 1, additional_information_s))\n                      , 0),\n    State = case( additional_information_s has 'error_state', toint(extract(\"<error_state>([0-9.]+)\", 1, additional_information_s))\n                      , additional_information_s has 'failure_reason', toint(extract(\"<failure_reason>Err ([0-9.]+), Level ([0-9.]+)\", 2, additional_information_s))\n                      , 0),\n    AdditionalInfo = additional_information_s, timeSlice = floor(TimeGenerated, timeSliceSize));\nprocessedData\n//Bin the data into 1h windows, taking the average of exeuction time\n| summarize round(avg(DurationMs), 2), min(TimeGenerated), max(TimeGenerated) by PrincipalName, ApplicationName, bin(TimeGenerated, timeSliceSize), ResourceId\n//Summarise by user and application and create list ready for anomaly detection\n| summarize make_list(avg_DurationMs, 10000), make_list(min_TimeGenerated, 10000), make_list(max_TimeGenerated, 10000) by PrincipalName, ApplicationName, ResourceId\n| extend series_decompose_anomalies(list_avg_DurationMs, scoreThreshold, -1, 'linefit')\n| mv-expand TimeAnomaly=series_decompose_anomalies_list_avg_DurationMs_ad_flag, WindowStart=list_min_TimeGenerated, WindowEnd=list_max_TimeGenerated\n| project WindowStart, WindowEnd, PrincipalName, ApplicationName, TimeAnomaly, ResourceId\n| where TimeAnomaly == 1 \n//Split the query here to see raw anomaly results\n//The next section will re-join back to the SQL diagnostics data to \n//display the queries executed within the anomalous windows identified\n| extend joinKey = strcat(PrincipalName, ApplicationName)\n| join kind=leftouter (\n    processedData\n    | project ApplicationName, PrincipalName, Statement, TimeGenerated, DurationMs, ResourceId, ClientIp, HostName\n    | extend joinKey = strcat(PrincipalName, ApplicationName)\n) on joinKey\n| where TimeGenerated between (todatetime(WindowStart) .. todatetime(WindowEnd))\n| project TimeGenerated, TimeAnomaly, WindowStart, WindowEnd, PrincipalName, ApplicationName, Statement, DurationMs, ResourceId, ClientIp, HostName\n| order by DurationMs desc\n| extend Name = tostring(split(PrincipalName, '@', 0)[0]), UPNSuffix = tostring(split(PrincipalName, '@', 1)[0])\n| extend Account_0_Name = Name\n| extend Account_0_UPNSuffix = UPNSuffix\n| extend IP_0_Address = ClientIp\n| extend Host_0_Hostname = HostName\n| extend CloudApplication_0_Name = ApplicationName\n| extend AzureResource_0_ResourceId = ResourceId\n```"
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
  - entityType: AzureResource
    fieldMappings:
      - identifier: ResourceId
        columnName: ResourceId
---

