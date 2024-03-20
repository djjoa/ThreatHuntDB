---
id: 13476066-24d0-4b19-8fd5-28fe42ab35f6
name: MultipleLdaps
description: |
  Detect multiple Active Directory LDAP queries made in bin time
  Replace 10 on line 1 with your desired thershold
  Replace 1m on line 2 with your desired bin time
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - IdentityQueryEvents
query: "```kusto\nlet Thershold = 10;\nlet BinTime = 1m;\nIdentityQueryEvents\n| where ActionType == \"LDAP query\"\n| parse Query with * \"Search Scope: \" SearchScope \", Base Object:\" BaseObject \", Search Filter: \" SearchFilter\n| summarize NumberOfLdapQueries = count(), NumberOfDistinctLdapQueries = dcount(SearchFilter) by DeviceName, bin(Timestamp, BinTime)\n| where NumberOfDistinctLdapQueries > Thershold \n```"
---

