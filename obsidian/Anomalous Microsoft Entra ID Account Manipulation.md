---
id: 8741deeb-332e-4061-8873-5086040920e3
name: Anomalous Microsoft Entra ID Account Manipulation
description: "'Adversaries may manipulate accounts to maintain access to victim systems. These actions include adding new accounts to high privilleged groups. \n Dragonfly 2.0, for example, added newly created accounts to the administrators group to maintain elevated access. The query below generates an \n output of all high Blast Radius users performing \"Update user\" (name change) to priveleged role, or where one or more features of the activitiy \n deviates from the user, his peers or the tenant profile.'\n"
requiredDataConnectors:
  - connectorId: BehaviorAnalytics
    dataTypes:
      - BehaviorAnalytics
  - connectorId: AzureActiveDirectory
    dataTypes:
      - AuditLogs
tactics:
  - Persistence
relevantTechniques:
  - T1098
query: "```kusto\n\n//Critical Roles can impersonate any user or app, can update passwords for users or service principals (if the role can let a user update passwords for privileged users, if an attacker compromises this user then attacker can update passwords for privileged users hence gaining more privileges so users with this role are equally critical)\n//High Roles are Administrators that can manage all aspects or permissions of important products but can't update credentials and impersonate another user/app\nlet critical = dynamic(['9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3','c4e39bd9-1100-46d3-8c65-fb160da0071f','158c047a-c907-4556-b7ef-446551a6b5f7','62e90394-69f5-4237-9190-012177145e10',\n'd29b2b05-8046-44ba-8758-1e26182fcf32','729827e3-9c14-49f7-bb1b-9608f156bbb8','966707d0-3269-4727-9be2-8c3a10f19b9d','194ae4cb-b126-40b2-bd5b-6091b380977d','fe930be7-5e62-47db-91af-98c3a49a38b1']);\nlet high = dynamic(['cf1c38e5-3621-4004-a7cb-879624dced7c','7495fdc4-34c4-4d15-a289-98788ce399fd','aaf43236-0c0d-4d5f-883a-6955382ac081','3edaf663-341e-4475-9f94-5c398ef6c070',\n'7698a772-787b-4ac8-901f-60d6b08affd2','b1be1c3e-b65d-4f19-8427-f6fa0d97feb9','9f06204d-73c1-4d4c-880a-6edb90606fd8','29232cdf-9323-42fd-ade2-1d097af3e4de','be2f45a1-457d-42af-a067-6ec1fa63bc45',\n'7be44c8a-adaf-4e2a-84d6-ab2649e08a13','e8611ab8-c189-46e8-94e1-60213ab1f814']);\nAuditLogs\n| where OperationName == \"Update user\"\n| mv-expand AdditionalDetails\n| mv-expand TargetResources\n| where AdditionalDetails.key == \"UserPrincipalName\"\n| mv-expand TargetResources\n| extend RoleId = tostring(TargetResources.modifiedProperties[0].newValue)\n| extend RoleName = tostring(TargetResources.modifiedProperties[1].newValue)\n| where RoleId in (critical,high)\n| where isnotempty(RoleId) or isnotempty(RoleName)\n| extend TargetId = tostring(TargetResources.id)\n| extend Target =  iff(tostring(TargetResources.userPrincipalName) has \"#EXT#\",replace(\"_\",\"@\",tostring(split(TargetResources.userPrincipalName, \"#\")[0])),TargetResources.userPrincipalName),tostring(TargetResources.userPrincipalName)\n| join kind=inner ( BehaviorAnalytics\n) on $left._ItemId == $right.SourceRecordId\n| where UsersInsights.BlastRadius == \"High\" or ActivityInsights has \"True\"\n| extend UserPrincipalName = iff(UserPrincipalName has \"#EXT#\",replace(\"_\",\"@\",tostring(split(UserPrincipalName, \"#\")[0])),UserPrincipalName), UserName = iff(UserName has \"#EXT#\",replace(\"_\",\"@\",tostring(split(UserPrincipalName, \"#\")[0])),UserName) \n| project TimeGenerated, UserName, UserPrincipalName, UsersInsights, ActivityType, ActionType, [\"TargetUser\"]=Target, RoleName, ActivityInsights, SourceIPAddress, SourceIPLocation, SourceDevice, DevicesInsights, ResourceId\n| extend timestamp = TimeGenerated, AccountCustomEntity = UserPrincipalName, IPCustomEntity = SourceIPAddress, ResourceCustomEntity = ResourceId\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: UserPrincipalName
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: SourceIPAddress
  - entityType: AzureResource
    fieldMappings:
      - identifier: ResourceId
        columnName: ResourceId
---

