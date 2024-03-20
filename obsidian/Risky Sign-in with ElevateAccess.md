---
id: 158b565b-411b-4dec-81de-2d2bcaf0c34c
name: Risky Sign-in with ElevateAccess
description: "Looks for users who had a risky sign in (based on Entra ID Identity Protection risk score) and then performed and ElevateAccess action. ElevateAccess operations can be used by Global Admins to obtain permissions over Azure resources. \n"
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - CloudAppEvents
      - AADSignInEventsBeta
tactics:
  - PrivilegeEscalation
query: "```kusto\nlet riskySignInLookback = 3d;\nlet elevatedUsers =\n( CloudAppEvents\n| where Timestamp > ago(1d)\n| where ApplicationId == 12260 // filter Azure Resource Manager events \n| where ActionType has \"elevateAccess\"\n| project  elevatedOperationTimestamp = Timestamp, AccountObjectId);\nlet hasElevatedUsers = isnotempty(toscalar(elevatedUsers));\nAADSignInEventsBeta\n| where hasElevatedUsers\n| where Timestamp > ago(riskySignInLookback)\n| where ErrorCode == 0\n| where RiskLevelDuringSignIn in (50, 100) //10 - low, 50 - medium, 100 - high)\n| join elevatedUsers on AccountObjectId\n| where elevatedOperationTimestamp > Timestamp\n| project LoginTime = Timestamp, elevatedOperationTimestamp, AccountObjectId, AccountDisplayName, riskScore = RiskLevelDuringSignIn\n```"
---

