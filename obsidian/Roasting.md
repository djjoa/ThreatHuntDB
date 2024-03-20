---
id: 17a34f6c-b3ba-42a0-810a-1746281e672d
name: Roasting
description: |
  Detect Active Directory LDAP queries that search for Kerberoasting (SPNs) or accounts with Kerberos preauthentication not required from Azure ATP, and try to get the process initiated the LDAP query from MDATP.
  Replace 389 on line 5 with LDAP port in your environment
  Replace true on line 6 to false if you want to include Nt Authority process
  This LDAP query cover Rubeus, Kerberoast, BloodHound tools
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - IdentityQueryEvents
      - DeviceNetworkEvents
query: "```kusto\nlet ASREP_ROASTING = \"userAccountControl:1.2.840.113556.1.4.803:=4194304\";\nlet ASREP_ROASTING1 = \"userAccountControl|4194304\";\nlet ASREP_ROASTING2 = \"userAccountControl&4194304\";\nlet KERBEROASTING = \"serviceprincipalname=*\";\nlet LDAP_PORT = 389;\nlet ExcludeNtAuthorityProcess = true;\nlet AzureAtpLdap = (\nIdentityQueryEvents\n| where ActionType == \"LDAP query\"\n| parse Query with * \"Search Scope: \" SearchScope \", Base Object:\" BaseObject \", Search Filter: \" SearchFilter\n| where SearchFilter contains ASREP_ROASTING or\nSearchFilter contains ASREP_ROASTING1 or\nSearchFilter contains ASREP_ROASTING2 or\nSearchFilter contains KERBEROASTING\n| extend Time = bin(Timestamp, 1s)\n| extend DeviceNameWithoutDomain = tolower(tostring(split(DeviceName, '.')[0])));\nlet MDAtpNetworkToProcess = (\nDeviceNetworkEvents\n| extend DeviceNameWithoutDomain = tolower(tostring(split(DeviceName, '.')[0]))\n| where RemotePort == LDAP_PORT\n| extend Time = bin(Timestamp, 1s)\n| extend isExclude = iff( ExcludeNtAuthorityProcess and InitiatingProcessAccountDomain == \"nt authority\" , true, false));\nAzureAtpLdap\n| join kind=leftouter (\nMDAtpNetworkToProcess ) on DeviceNameWithoutDomain, Time \n| where isExclude == false or isnull(isExclude)\n```"
---

