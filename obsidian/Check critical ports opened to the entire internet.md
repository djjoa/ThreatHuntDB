---
id: 66d494c0-233c-438a-9b1b-5fe839790d38
name: Check critical ports opened to the entire internet
description: |
  'Discover all critical ports from a list having rules like 'Any' for sourceIp, which means that they are opened to everyone. Critial ports should not be opened to everyone, and should be filtered.'
requiredDataConnectors:
  - connectorId: WAF
    dataTypes:
      - AzureDiagnostics
tactics:
  - InitialAccess
query: "```kusto\n\n//Check critical ports opened to the entire internet\nAzureDiagnostics\n| where Category == \"NetworkSecurityGroupEvent\" \n| where direction_s == \"In\" \n| where conditions_destinationPortRange_s in (\n\"22\",\"22-22\"          //SSH\n,\"3389\",\"3389-3389\"   //RDP\n,\"137\",\"137-137\"      //NetBIOS\n,\"138\",\"138-138\"      //NetBIOS\n,\"139\",\"139-139\"      //SMB\n,\"53\",\"53-53\"         //DNS\n,\"3020\",\"3020-3020\"   //CIFS\n,\"3306\",\"3306-3306\"   //MySQL\n,\"1521\",\"1521-1521\"   //Oracle Database\n,\"2483\",\"2483-2483\"   //Oracle Database\n,\"5432\",\"5432-5432\"   //PostgreSQL\n,\"389\",\"389-389\"      //LDAP\n,\"27017\",\"27017-27017\"//MongoDB\n,\"20\",\"20-20\"         //FTP\n,\"21\",\"21-21\"         //FTP\n,\"445\",\"445-445\"      //Active Directory\n,\"161\",\"161-161\"      //SNMP\n,\"25\",\"25-25\"         //SMTP\n)\n or (conditions_destinationPortRange_s == \"0-65535\" and conditions_sourcePortRange_s == \"0-65535\")\n| where priority_d < 65000    //Not to check the Azure defaults\n| where conditions_sourceIP_s == \"0.0.0.0/0,0.0.0.0/0\" or conditions_sourceIP_s == \"0.0.0.0/0\" //With rules Any/Any\n| where type_s !~ \"block\"\n| order by TimeGenerated desc\n| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), count() by OperationName, systemId_g, vnetResourceGuid_g, subnetPrefix_s, macAddress_s, primaryIPv4Address_s, ruleName_s, direction_s, priority_d, type_s, conditions_destinationIP_s, conditions_destinationPortRange_s, conditions_sourceIP_s, conditions_sourcePortRange_s, ResourceId\n| extend timestamp = StartTime\n```"
version: 1.0.0
metadata:
  source:
    kind: Community
  author:
    name: Alethor
  support:
    tier: Community
  categories:
    domains: ["Security - Threat Protection"]
---

