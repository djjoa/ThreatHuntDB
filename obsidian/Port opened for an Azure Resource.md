---
id: 9e146876-e303-49af-b847-b029d1a66852
name: Port opened for an Azure Resource
description: |
  'Identifies what ports may have been opened for a given Azure Resource over the last 7 days'
requiredDataConnectors:
  - connectorId: AzureActivity
    dataTypes:
      - AzureActivity
tactics:
  - CommandAndControl
  - Impact
relevantTechniques:
  - T1071
  - T1571
  - T1496
query: "```kusto\nlet lookback = 7d;\nAzureActivity\n| where TimeGenerated >= ago(lookback)\n| where OperationNameValue has_any (\"ipfilterrules\", \"securityRules\", \"publicIPAddresses\", \"firewallrules\") and OperationNameValue endswith \"write\"\n// Choosing Accepted here because it has the Rule Attributes included\n| where ActivityStatusValue == \"Accepted\" \n// If there is publicIP info, include it\n| extend parsed_properties = parse_json(tostring(parse_json(Properties).responseBody)).properties\n| extend publicIPAddressVersion = case(Properties has_cs 'publicIPAddressVersion',tostring(parsed_properties.publicIPAddressVersion),\"\")\n| extend publicIPAllocationMethod = case(Properties has_cs 'publicIPAllocationMethod',tostring(parsed_properties.publicIPAllocationMethod),\"\")\n// Include rule attributes for context\n| extend access = case(Properties has_cs 'access',tostring(parsed_properties.access),\"\")\n| extend description = case(Properties has_cs 'description',tostring(parsed_properties.description),\"\")\n| extend destinationPortRange = case(Properties has_cs 'destinationPortRange',tostring(parsed_properties.destinationPortRange),\"\")\n| extend direction = case(Properties has_cs 'direction',tostring(parsed_properties.direction),\"\")\n| extend protocol = case(Properties has_cs 'protocol',tostring(parsed_properties.protocol),\"\")\n| extend sourcePortRange = case(Properties has_cs 'sourcePortRange',tostring(parsed_properties.sourcePortRange),\"\")\n| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), ResourceIds = make_set(_ResourceId,100) by Caller, CallerIpAddress, Resource, ResourceGroup, \nActivityStatusValue, ActivitySubstatus, SubscriptionId, access, description, destinationPortRange, direction, protocol, sourcePortRange, publicIPAddressVersion, publicIPAllocationMethod\n| extend Name = tostring(split(Caller,'@',0)[0]), UPNSuffix = tostring(split(Caller,'@',1)[0])\n| extend Account_0_Name = Name\n| extend Account_0_UPNSuffix = UPNSuffix\n| extend IP_0_Address = CallerIpAddress\n```"
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
        columnName: CallerIpAddresss
version: 2.0.1
---

