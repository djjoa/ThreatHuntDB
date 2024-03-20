---
id: 0278e3b8-9899-45c5-8928-700cd80d2d80
name: Common deployed resources
description: |
  'This query identifies common deployed resources in Azure, like resource names and groups. It can be used with other suspicious deployment signals to evaluate if a resource is commonly deployed or unique.'
description_detailed: "'This query looks for common deployed resources (resource name and resource groups) and can be used\nin combination with other signals that show suspicious deployment to evaluate if the resource is one\nthat is commonly being deployed/created or unique.\nTo understand the basket() function better see - https://docs.microsoft.com/azure/data-explorer/kusto/query/basketplugin' \n"
requiredDataConnectors:
  - connectorId: AzureActivity
    dataTypes:
      - AzureActivity
tactics:
  - Impact
relevantTechniques:
  - T1496
query: "```kusto\nAzureActivity\n| where OperationNameValue has_any (@\"deployments/write\", @\"virtualMachines/write\")  \n| where ActivityStatusValue =~ \"Succeeded\"\n| summarize by bin(TimeGenerated,1d), Resource, ResourceGroup, ResourceId, OperationNameValue, Caller\n| evaluate basket()\n| where isnotempty(Caller) and isnotempty(Resource) and isnotempty(TimeGenerated)\n| order by Percent desc, TimeGenerated desc\n| extend Name = tostring(split(Caller,'@',0)[0]), UPNSuffix = tostring(split(Caller,'@',1)[0])\n| extend Account_0_Name = Name\n| extend Account_0_UPNSuffix = UPNSuffix\n| extend AzureResource_0_ResourceId = ResourceId\n// remove comments below on filters if the goal is to see more common or more rare Resource, Resource Group and Caller combinations\n//| where Percent <= 40 // <-- more rare\n//| where Percent >= 60 // <-- more common\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: Name
      - identifier: UPNSuffix
        columnName: UPNSuffix
  - entityType: AzureResource
    fieldMappings:
      - identifier: ResourceId
        columnName: ResourceId
version: 2.0.1
---

