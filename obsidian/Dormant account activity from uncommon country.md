---
id: 7c303408-f913-42f8-8d7b-9eb64a229c4d
name: Dormant account activity from uncommon country
description: |
  'Shows dormant accounts (not active in the last 180 days) that connect from a country for the first time and the country is uncommon in the tenant or is the first time the ISP is used.'
requiredDataConnectors:
  - connectorId: BehaviorAnalytics
    dataTypes:
      - BehaviorAnalytics
tactics:
relevantTechniques:
query: "```kusto\nBehaviorAnalytics\n| where UsersInsights.IsDormantAccount == True\n| where ActivityInsights.FirstTimeUserConnectedFromCountry == True\n| where ActivityInsights.CountryUncommonlyConnectedFromInTenant == True \n  or ActivityInsights.FirstTimeConnectionViaISPInTenant == True\n| extend AadUserId = UsersInsights.AccountObjectID\n| extend Account_0_AadUserId = AadUserId\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: AadUserId
        columnName: AadUserId
version: 2.0.0
---

