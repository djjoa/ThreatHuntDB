---
id: e0944dec-3c92-4b2d-8e81-a950afeaba69
name: Time Based SQL Query Size Anomaly
description: |
  'This hunting query uses series decompose anomaly to identify periods of time where a given user account and application combination is used to send an anomalous number of parameters or SQL query tokens to the server. This query is designed to be run against application and username combinations that are used by SQL applications, such as content management systems (Wordpress, Joomla, TYPO3, etc.).'
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
query: |-
  ```kusto
  let timeRange = 30d;
  //How frequently the query averages data for an average execution time
  let timeSliceSize = 1h;
  //Anomaly decompose threshold, 10 by default
  let scoreThreshold = 10;
  //Time range to use for grouping events to detect anomalies
  let resolution = 1d;
  let processedData = materialize (
      AzureDiagnostics
      | where TimeGenerated > ago(timeRange)
      | where Category == 'SQLSecurityAuditEvents' and action_id_s has_any ("RCM", "BCM") // Keep only SQL affected rows
      | project TimeGenerated, PrincipalName = server_principal_name_s, ClientIp = client_ip_s, HostName = host_name_s, ResourceId,
      ApplicationName = application_name_s, ActionName = action_name_s, Database = strcat(LogicalServerName_s, '/', database_name_s),
      IsSuccess = succeeded_s, DurationMs = duration_milliseconds_d, AffectedRows = affected_rows_d,
      ResponseRows = response_rows_d, Statement = statement_s,
      Error = case( additional_information_s has 'error_code', toint(extract("<error_code>([0-9.]+)", 1, additional_information_s))
                        , additional_information_s has 'failure_reason', toint(extract("<failure_reason>Err ([0-9.]+)", 1, additional_information_s))
                        , 0),
      State = case( additional_information_s has 'error_state', toint(extract("<error_state>([0-9.]+)", 1, additional_information_s))
                        , additional_information_s has 'failure_reason', toint(extract("<failure_reason>Err ([0-9.]+), Level ([0-9.]+)", 2, additional_information_s))
                        , 0),
      AdditionalInfo = additional_information_s, timeSlice = floor(TimeGenerated, timeSliceSize));
  processedData
  //Splitting on "=" provides a good estimate to the number of parameters in the query
  | extend parameters = countof(Statement, "=")
  //Splitting on space provides a good estimate to the tokens in the query
  | extend tokens = array_length(split(Statement, " "))
  //Bin the data into 1 day windows, taking the average of tokens and parameters for that user and application during the period
  | summarize round(avg(tokens), 2), round(avg(parameters),2), min(TimeGenerated), max(TimeGenerated) by PrincipalName, ApplicationName, bin(TimeGenerated, resolution)
  //Summarise by user and application and create lists ready for anomaly detection
  | summarize make_list(avg_tokens, 10000), make_list(avg_parameters, 10000), make_list(min_TimeGenerated, 10000), make_list(max_TimeGenerated, 10000) by PrincipalName, ApplicationName
  | extend series_decompose_anomalies(list_avg_tokens, scoreThreshold, -1, 'linefit'), series_decompose_anomalies(list_avg_parameters, scoreThreshold, -1, 'linefit')
  | mv-expand TokenAnomaly=series_decompose_anomalies_list_avg_tokens_ad_flag, ParameterAnomaly=series_decompose_anomalies_list_avg_parameters_ad_flag, WindowStart=list_min_TimeGenerated, WindowEnd=list_max_TimeGenerated
  | project WindowStart, WindowEnd, PrincipalName, ApplicationName, TokenAnomaly, ParameterAnomaly
  //Enable to detect SQL statement token anomalies
  | where TokenAnomaly == 1 or TokenAnomaly == -1
  //Enable to detect SQL statement parameter anomalies
  //| where ParameterAnomaly == 1 or ParameterAnomaly == -1
  //Split the query here to see raw anomaly results
  //The next section will re-join back to the SQL diagnostics data to
  //display the queries executed within the anomalous windows identified
  | extend joinKey = strcat(PrincipalName, ApplicationName)
  | join kind=leftouter (
      processedData
      | project ApplicationName, PrincipalName, Statement, TimeGenerated
      | extend joinKey = strcat(PrincipalName, ApplicationName)
  ) on joinKey
  | where TimeGenerated between (todatetime(WindowStart) .. todatetime(WindowEnd))
  | extend Parameters = countof(Statement, "=")
  | extend Tokens = array_length(split(Statement, " "))
  | project TimeGenerated, ParameterAnomaly, Parameters, TokenAnomaly, Tokens, WindowStart, WindowEnd, PrincipalName, ApplicationName, Statement
  | order by Tokens desc, Parameters desc
  | extend Name = tostring(split(PrincipalName, '@', 0)[0]), UPNSuffix = tostring(split(PrincipalName, '@', 1)[0])
  | extend Account_0_Name = Name
  | extend Account_0_UPNSuffix = UPNSuffix
  | extend CloudApplication_0_Name = ApplicationName
  ```
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: Name
      - identifier: UPNSuffix
        columnName: UPNSuffix
  - entityType: CloudApplication
    fieldMappings:
      - identifier: Name
        columnName: ApplicationName
version: 1.0.1
---

