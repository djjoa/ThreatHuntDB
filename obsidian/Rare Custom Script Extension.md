---
id: 81fd68a2-9ad6-4a1c-7bd7-18efe5c99081
name: Rare Custom Script Extension
description: |
  'The Custom Script Extension in Azure executes scripts on VMs, useful for post-deployment tasks. Scripts can be from various sources and could be used maliciously. The query identifies rare custom script extensions executed in your environment.'
description_detailed: |
  'The Custom Script Extension downloads and executes scripts on Azure virtual machines. This extension is useful for post deployment       configuration, software installation, or any other configuration or management tasks.
   Scripts could be downloaded from external links, Azure storage, GitHub, or provided to the Azure portal at extension run time. This could also be used maliciously by an attacker.
   The query tries to identify rare custom script extensions that have been executed in your environment'
requiredDataConnectors:
  - connectorId: AzureActivity
    dataTypes:
      - AzureActivity
tactics:
  - Execution
relevantTechniques:
  - T1059
query: |-
  ```kusto
  let starttime = todatetime('{{StartTimeISO}}');
  let endtime = todatetime('{{EndTimeISO}}');
  let Lookback = starttime - 14d;
  let CustomScriptExecution = AzureActivity
  | where TimeGenerated >= Lookback
  | where OperationName =~ "Create or Update Virtual Machine Extension"
  | extend parsed_properties = parse_json(Properties)
  | extend Settings = tostring((parse_json(tostring(parsed_properties.responseBody)).properties).settings)
  | parse Settings with * 'fileUris":[' FileURI "]" *
  | parse Settings with * 'commandToExecute":' commandToExecute '}' *
  | extend message_ = tostring((parse_json(tostring(parsed_properties.statusMessage)).error).message);
  let LookbackCustomScriptExecution = CustomScriptExecution
  | where TimeGenerated >= Lookback and TimeGenerated < starttime
  | where isnotempty(FileURI) and isnotempty(commandToExecute)
  | summarize max(TimeGenerated), OperationCount = count() by Caller, Resource, CallerIpAddress, FileURI, commandToExecute;
  let CurrentCustomScriptExecution = CustomScriptExecution
  | where TimeGenerated between (starttime..endtime)
  | where isnotempty(FileURI) and isnotempty(commandToExecute)
  | project TimeGenerated, ActivityStatus, OperationId, CorrelationId, ResourceId, CallerIpAddress, Caller, OperationName, Resource, ResourceGroup, FileURI, commandToExecute, FailureMessage = message_, HTTPRequest, Settings;
  let RareCustomScriptExecution =  CurrentCustomScriptExecution
  | join kind= leftanti (LookbackCustomScriptExecution) on Caller, CallerIpAddress, FileURI, commandToExecute;
  let IPCheck = RareCustomScriptExecution
  | summarize arg_max(TimeGenerated, OperationName), OperationIds = make_set(OperationId,100), CallerIpAddresses = make_set(CallerIpAddress,100) by ActivityStatus, CorrelationId, ResourceId, Caller, Resource, ResourceGroup, FileURI, commandToExecute, FailureMessage
  | extend IPArray = array_length(CallerIpAddresses);
  //Get IPs for later summarization so all associated CorrelationIds and Caller actions have an IP.  Success and Fails do not always have IP
  let multiIP = IPCheck | where IPArray > 1
  | mv-expand CallerIpAddresses | extend CallerIpAddress = tostring(CallerIpAddresses)
  | where isnotempty(CallerIpAddresses);
  let singleIP = IPCheck | where IPArray <= 1
  | mv-expand CallerIpAddresses | extend CallerIpAddress = tostring(CallerIpAddresses);
  let FullDetails = singleIP | union multiIP;
  //Get IP address associated with successes and fails with no IP listed
  let IPList = FullDetails | where isnotempty(CallerIpAddress) | summarize by CorrelationId, Caller, CallerIpAddress;
  let EmptyIP = FullDetails | where isempty(CallerIpAddress) | project-away CallerIpAddress;
  let IpJoin = EmptyIP | join kind= leftouter (IPList) on CorrelationId, Caller | project-away CorrelationId1, Caller1;
  let nonEmptyIP = FullDetails | where isnotempty(CallerIpAddress);
  nonEmptyIP | union IpJoin
  // summarize all activities with a given CorrelationId and Caller together so we can provide a singular result
  | summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), ActivityStatusSet = make_set(ActivityStatus,100), OperationIds = make_set(OperationIds,100), FailureMessages = make_set(FailureMessage,100) by CorrelationId, ResourceId, CallerIpAddress, Caller, Resource, ResourceGroup, FileURI, commandToExecute
  | extend Name = tostring(split(Caller,'@',0)[0]), UPNSuffix = tostring(split(Caller,'@',1)[0])
  | extend Account_0_Name = Name
  | extend Account_0_UPNSuffix = UPNSuffix
  | extend IP_0_Address = CallerIpAddress
  ```
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
        columnName: CallerIpAddress
version: 2.0.1
---

