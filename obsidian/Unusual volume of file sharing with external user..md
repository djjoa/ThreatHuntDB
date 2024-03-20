---
id: bafc1446-1cc4-4f6d-ad76-1250b8c3b60c
name: Unusual volume of file sharing with external user.
description: "This query looks for users sharing access to files with external users. \nThis applies to SharePoint and OneDrive users.\nAudit event and Cloud application identifier references.  \nReference - https://learn.microsoft.com/microsoft-365/compliance/audit-log-sharing?view=o365-worldwide\nReference - https://learn.microsoft.com/azure/sentinel/entities-reference#cloud-application-identifiers\n"
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - CloudAppEvents
      - AADSignInEventsBeta
tactics:
  - Exfiltration
query: "```kusto\nlet usefulExtn= pack_array('csv', 'doc', 'docm', 'docx', 'dot', 'dotx', 'eml', 'pdf', 'pot', 'potm', 'potx', 'ppam', 'pps', 'ppsm', 'ppsx', 'ppt', 'pptm', 'pptx',\n  'psd', 'pst', 'pub', 'ppk', 'rar', 'rtf', 'txt', 'vsd', 'vsdm', 'vsdx', 'vss', 'vssm', 'vst', 'vstm', 'vstx', 'xla', 'xlam', 'xll', 'xlm', 'xls', 'xlsm', 'xlsx', 'xlt',\n  'xltm', 'xltx', 'xps', 'zip', 'xsl');\nlet sharingPerms= pack_array(\"AnonymousLinkCreated\", \"SharingInvitationCreated\", \"SharingSet\");\nlet relevantAppIds = pack_array(int(20892), int(15600)); // App Ids for SharePoint and OneDrive\nlet timeWindow = 24h;\nlet timeNow = now();\n//\nlet riskyUsers= // Look for users with risky sign-ins\n  AADSignInEventsBeta    \n  | where Timestamp between ((timeNow - timeWindow) .. (timeNow))\n  | where isnotempty(AccountObjectId) and isnotempty(RequestId) // In AADSignInEventsBeta, the SessionId column has inaccurate data and instead the RequestId has the actual Session identifier\n  | where ErrorCode == 0\n  | where RiskLevelDuringSignIn >=80\n  | project RiskLevelDuringSignIn, AccountObjectId, Timestamp, SessionId=RequestId\n  ;\nlet hasUsers = isnotempty(toscalar(riskyUsers));\n//\nCloudAppEvents // look for file sharing activity and scope it to risky users\n  | where hasUsers\n  | where Timestamp between ((timeNow - timeWindow) .. (timeNow))\n  | where ApplicationId in (relevantAppIds)\n  | where AccountObjectId in (riskyUsers)\n  | where ActionType in (sharingPerms)\n  | extend SourceFileExtension = tostring(RawEventData.SourceFileExtension), SourceFileName=tostring(RawEventData.SourceFileName), TargetGroup=tostring(RawEventData.TargetUserOrGroupType)\n  | where SourceFileExtension has_any (usefulExtn)\n  | where TargetGroup == \"Guest\"\n  //\n  | summarize Count = countif(isnotempty( SourceFileName)), (Timestamp, ReportId)=arg_min(Timestamp, ReportId) ,FileNames = make_set(SourceFileName, 10) ,FileExt = make_set(SourceFileExtension, 10) by AccountObjectId, AccountDisplayName, ApplicationId, ActionType, Time = bin(Timestamp, 10m)\n  | summarize TotalCount = countif(Count > 10) , (Timestamp, ReportId)=arg_min(Timestamp, ReportId) by AccountObjectId, AccountDisplayName, ApplicationId\n  | where TotalCount > 1```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: AadUserId
        columnName: AccountObjectId
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountDisplayName
  - entityType: CloudApplication
    fieldMappings:
      - identifier: AppId
        columnName: ApplicationId
customDetails:
  Count: TotalCount
---
