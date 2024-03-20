---
id: 611ebbc2-c789-42ad-93e3-6dc02bfa5e3d
name: Unusual volume of file deletion by user.
description: |
  This query looks for users performing file deletion activities. Spikes in file deletion observed from risky sign-in sessions are flagged here.
  This applies to SharePoint and OneDrive users.
  Audit event and Cloud application identifier references.
  Reference - https://learn.microsoft.com/microsoft-365/compliance/audit-log-activities?view=o365-worldwide
  Reference - https://learn.microsoft.com/azure/sentinel/entities-reference#cloud-application-identifiers
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - CloudAppEvents
      - AADSignInEventsBeta
tactics:
  - Impact
query: "```kusto\nlet relevantOperations = pack_array(\"FileDeleted\", \"FileRecycled\", \"FileDeletedFirstStageRecycleBin\", \"FileDeletedSecondStageRecycleBin\", \"FileVersionsAllMinorsRecycled\", \"FileVersionRecycled\", \"FileVersionsAllRecycled\");\nlet relevantAppIds = pack_array(int(20892), int(15600)); // App Ids for SharePoint and OneDrive\nlet timeWindow = 24h;\nlet timeNow = now();\n//\nlet riskyUsers= // Look for users with risky sign-ins\n  AADSignInEventsBeta    \n  | where Timestamp between ((timeNow - timeWindow) .. (timeNow))\n  | where isnotempty(AccountObjectId) and isnotempty(RequestId) // In AADSignInEventsBeta, the SessionId column has inaccurate data and instead the RequestId has the actual Session identifier\n  | where ErrorCode == 0\n  | where RiskLevelDuringSignIn >=80\n  | project RiskLevelDuringSignIn, AccountObjectId, Timestamp, SessionId=RequestId\n  ;\nlet hasUsers = isnotempty(toscalar(riskyUsers));\n//\nlet deleteEvents = // look for file deletion activity and scope it to risky users\n  CloudAppEvents\n  | where hasUsers\n  | where Timestamp between ((timeNow - timeWindow) .. (timeNow))\n  | where ApplicationId in (relevantAppIds)\n  | where isnotempty(AccountObjectId)\n  | where AccountObjectId in (riskyUsers)\n  | where ActionType in (relevantOperations)\n  | extend SessionId= tostring(RawEventData.AppAccessContext.AADSessionId)\n  | where isnotempty(SessionId)\n  | project AccountObjectId, AccountDisplayName, ApplicationId, SessionId, ActionType, Timestamp, ReportId\n  ;   \n //\ndeleteEvents  \n| join kind=leftsemi riskyUsers on AccountObjectId, SessionId\n| summarize Count=count() , (Timestamp, ReportId)=arg_min(Timestamp, ReportId) by AccountObjectId, AccountDisplayName, ApplicationId, ActionType, Time=bin(Timestamp, 5m)\n// look for only those scoped users who have generated an increase in file deletion activity.\n| summarize TotalCount= countif(Count > 50), (Timestamp, ReportId)=arg_min(Timestamp, ReportId) by AccountObjectId, AccountDisplayName, ApplicationId \n| where TotalCount >= 3\n| project AccountObjectId, AccountDisplayName, ApplicationId, TotalCount, ReportId, Timestamp\n| extend NTDomain = tostring(split(AccountDisplayName,'\\\\',0)[0]), Name = tostring(split(AccountDisplayName,'\\\\',1)[0])\n| extend Account_0_Name = Name\n| extend Account_0_NTDomain = NTDomain\n| extend Account_0_AadUserId = AccountObjectId\n| extend CloudApplication_0_AppId = ApplicationId\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: AadUserId
        columnName: AccountObjectId
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: Name
      - identifier: NTDomain
        columnName: NTDomain
  - entityType: CloudApplication
    fieldMappings:
      - identifier: AppId
        columnName: ApplicationId
customDetails:
  Count: TotalCount
version: 1.0.0
---

