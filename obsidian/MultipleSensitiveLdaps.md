---
id: 36582cd7-ddd2-43bc-be79-293a61c42cbe
name: MultipleSensitiveLdaps
description: |
  Detect multiple sensitive Active Directory LDAP queries made in bin time
  Sensitive queries defined as Roasting or sensitive objects queries
  Replace 10 on line 6 with your desired thershold
  Replace 1m on line 7 with your desired bin time
  This LDAP query cover Rubeus, Kerberoast, BloodHound tools
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - IdentityQueryEvents
query: "```kusto\nlet SensitiveObjects = \"[\\\"Administrators\\\", \\\"Domain Controllers\\\", \\\"Domain Admins\\\", \\\"Account Operators\\\", \\\"Backup Operators\\\", \\\"DnsAdmin\\\", \\\"Enterprise Admins\\\", \\\"Group Policy Creator Owners\\\"]\";\nlet ASREP_ROASTING = \"userAccountControl:1.2.840.113556.1.4.803:=4194304\";\nlet ASREP_ROASTING1 = \"userAccountControl|4194304\";\nlet ASREP_ROASTING2 = \"userAccountControl&4194304\";\nlet KERBEROASTING = \"serviceprincipalname=*\";\nlet Thershold = 10;\nlet BinTime = 1m;\nlet SensitiveQueries = (\nIdentityQueryEvents\n| where ActionType == \"LDAP query\"\n| parse Query with * \"Search Scope: \" SearchScope \", Base Object:\" BaseObject \", Search Filter: \" SearchFilter\n| where SensitiveObjects contains QueryTarget or SearchFilter contains \"admincount=1\");\nlet Roasting = (\nIdentityQueryEvents\n| where ActionType == \"LDAP query\"\n| parse Query with * \"Search Scope: \" SearchScope \", Base Object:\" BaseObject \", Search Filter: \" SearchFilter\n| where SearchFilter contains ASREP_ROASTING or\nSearchFilter contains ASREP_ROASTING1 or\nSearchFilter contains ASREP_ROASTING2 or\nSearchFilter contains KERBEROASTING);\nunion SensitiveQueries, Roasting\n| summarize NumberOfLdapQueries = count(), NumberOfDistinctLdapQueries = dcount(SearchFilter) by DeviceName, bin(Timestamp, BinTime)\n| where NumberOfDistinctLdapQueries > Thershold \n```"
---

