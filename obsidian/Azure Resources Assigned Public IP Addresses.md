---
id: 8d5996b2-7d4c-4dcf-bb0d-0d7fdf0e2c75
name: Azure Resources Assigned Public IP Addresses
description: "'This query identifies instances when public IP addresses are assigned to Azure Resources and show connections to those resources.\nResources: \nhttps://docs.microsoft.com/azure/azure-monitor/insights/azure-networking-analytics\nhttps://docs.microsoft.com/azure/network-watcher/traffic-analytics-schema'\n"
requiredDataConnectors:
  - connectorId: AzureActivity
    dataTypes:
      - AzureActivity
  - connectorId: AzureNetworkWatcher
    dataTypes:
      - AzureNetworkAnalytics_CL
tactics:
  - Impact
relevantTechniques:
  - T1496
query: "```kusto\nlet OperationNames = dynamic([\"microsoft.compute/virtualMachines/write\", \"microsoft.resources/deployments/write\"]);\nAzureActivity\n// We look for any Operation that modified and then was accepted or succeeded where a public ip address component is referenced\n| where OperationNameValue in~ (OperationNames)\n| where ActivityStatusValue has_any (\"Succeeded\", \"Accepted\")\n| where Properties contains \"publicipaddress\"\n//| extend frontendIPConfigurations = Properties.responseBody.properties.frontendIPConfigurations\n// parsing the publicIPAddress from Properties. It is only available if the allocation method is Static.\n| parse Properties with * \"publicIPAddress\\\\\" PublicIPAddressParse\n| extend parsedProperties_ = parse_json(tostring(parse_json(Properties).responseBody)).properties\n| extend publicIPAddress_ = tostring(parse_json(tostring(parsedProperties_)).ipAddress) \n| extend publicIPAddressVersion_ = tostring(parse_json(tostring(parsedProperties_)).publicIPAddressVersion) \n| extend publicIPAllocationMethod_ = tostring(parse_json(tostring(parsedProperties_)).publicIPAllocationMethod) \n| extend scope_ = tostring(parse_json(Authorization).scope) \n| project TimeGenerated, OperationNameValue, publicIPAllocationMethod_ , publicIPAddressVersion_, scope_ , Caller, CallerIpAddress, ActivityStatusValue, Resource \n// Join in the AzureNetworkAnalytics so that we can determine if any connections were made via the public ip address and get the currently assigned ip address when allocation method is Dynamic\n| join kind= inner (\nunion isfuzzy=true\n(AzureNetworkAnalytics_CL\n// Controlling for Schema Version and later parsing - This is Version 2 and Public IPs only\n| where isnotempty(FASchemaVersion_s) and isnotempty(DestPublicIPs_s)\n| extend SchemaVersion = FASchemaVersion_s\n| extend PublicIPs = tostring(split(DestPublicIPs_s,\"|\")[0])\n| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), FirstProcessedTimeUTC = min(FlowStartTime_t), LastProcessedTimeUtc = max(FlowEndTime_t), \nRegions = make_set(Region_s, 1000), AzureRegions = make_set(AzureRegion_s, 1000), VMs = make_set(VM_s, 1000), MACAddresses = make_set(MACAddress_s, 1000), PublicIPs = make_set(PublicIPs, 1000), DestPort = make_set(DestPort_d, 1000), SrcIP = make_set(SrcIP_s, 1000), \nActivityCount = count() by NSGRule_s, NSGList_s, SubNet = Subnet1_s, FlowDirection_s, Subscription = Subscription1_g, Tags_s, SchemaVersion\n//NSGList_s contains the subscription ID, remove that as we already have a field for this and now it will match what we get for SchemaVersion 1\n| extend NSG = case(isnotempty(NSGList_s), strcat(split(NSGList_s, \"/\")[-2],\"/\",split(NSGList_s, \"/\")[-1]), \"NotAvailable\")\n// Depending on the SchemaVersion, we will need to provide the NSG_Name for matching against the resource identified in AzureActivity\n| extend NSG_Name = tostring(split(NSG, \"/\")[-1])\n),\n(\nAzureNetworkAnalytics_CL \n// Controlling for Schema Version and later parsing - This is Version 1\n| where isempty(FASchemaVersion_s)\n// Controlling for public IPs only\n| where isnotempty(PublicFrontendIPs_s) or isnotempty(PublicIPAddresses_s)\n| where PublicFrontendIPs_s != \"null\" or PublicIPAddresses_s != \"null\"\n| extend SchemaVersion = SchemaVersion_s\n// The Public IP can be indicated in one of 2 locations, assigning here for easy union results\n| extend PublicIPs = case(isnotempty(PublicFrontendIPs_s), PublicFrontendIPs_s,\nPublicIPAddresses_s) \n| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), FirstProcessedTimeUTC = min(TimeProcessed_t), LastProcessedTimeUtc = max(TimeProcessed_t), \nRegions = make_set(Region_s, 1000), AzureRegions = make_set(DiscoveryRegion_s, 1000), VMs = make_set(VirtualMachine_s, 1000), MACAddresses = make_set(MACAddress_s, 1000), PublicIPs = make_set(PublicIPs, 1000), \nSrcIP = make_set(PrivateIPAddresses_s, 1000), Name = make_set(Name_s, 1000), DestPort = make_set(DestinationPortRange_s, 1000),\nActivityCount = count() by NSG = NSG_s, SubNet = Subnetwork_s, Subscription = Subscription_g, Tags_s, SchemaVersion\n// Some events don't have an NSG listed, populating so it is clear it is not available in the datatype\n| extend NSG = case(isnotempty(NSG), NSG, \"NotAvailable\")\n// Depending on the SchemaVersion, we will need to provide the NSG_Name for matching against the resource identified in AzureActivity\n| extend NSG_Name = tostring(split(NSG, \"/\")[-1])\n)\n| project StartTimeUtc, EndTimeUtc, FirstProcessedTimeUTC, LastProcessedTimeUtc, PublicIPs, NSG, NSG_Name, SrcIP, DestPort, SubNet, Name, VMs, MACAddresses, ActivityCount, Regions, AzureRegions, Subscription, Tags_s, SchemaVersion\n) on $left.Resource == $right.NSG_Name\n| extend UserName = iff(Caller contains '@', tostring(split(Caller, '@')[0]), '')\n| extend UPNSuffix = iff(Caller contains '@', tostring(split(Caller, '@')[1]), '')\n| extend AadUserId = iff(Caller !contains '@', tostring(Caller), '')\n| extend Account_0_Name = Caller\n| extend Account_0_UPNSuffix = UPNSuffix\n| extend Account_0_AadUserId = AadUserId\n| extend IP_0_Address = CallerIpAddress\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: Caller
      - identifier: UPNSuffix
        columnName: UPNSuffix
      - identifier: AadUserId
        columnName: AadUserId
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: CallerIpAddress
version: 1.0.1
---

