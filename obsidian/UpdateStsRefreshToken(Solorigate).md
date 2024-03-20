---
id: 634dfbd6-0a42-40da-854e-2161cf137f14
name: UpdateStsRefreshToken[Solorigate]
description: |
  This will show Active Directory Security Token Service (STS) refresh token modifications by Service Principals and Applications other than DirectorySync. Refresh tokens are used to validate identification and obtain access tokens. This event is most often generated when legitimate administrators troubleshoot frequent Entra ID user sign-ins but may also be generated as a result of malicious token extensions. Confirm that the activity is related to an administrator legitimately modifying STS refresh tokens and check the new token validation time period for high values.
  Query insprired by Azure Sentinel detection https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/StsRefreshTokenModification.yaml
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - CloudAppEvents
tactics:
  - Defense evasion
tags:
  - Solorigate
query: "```kusto\nCloudAppEvents \n| where ActionType == \"Update StsRefreshTokenValidFrom Timestamp.\"\n| where RawEventData !has \"Directorysync\"\n| extend displayName = RawEventData.ModifiedProperties[0].Name  \n| where displayName == \"StsRefreshTokensValidFrom\"\n| extend oldValue = RawEventData.ModifiedProperties[0].OldValue\n| extend newValue = RawEventData.ModifiedProperties[0].NewValue\n| extend oldStsRefreshValidFrom = todatetime(parse_json(tostring(oldValue))[0])\n| extend newStsRefreshValidFrom = todatetime(parse_json(tostring(newValue))[0])\n| extend tokenMinutesAdded = datetime_diff('minute',newStsRefreshValidFrom,oldStsRefreshValidFrom)\n| extend tokenMinutesRemaining = datetime_diff('minute',Timestamp,newStsRefreshValidFrom)\n| extend Role = parse_json(RawEventData.Actor[-1]).ID\n| distinct AccountObjectId, AccountDisplayName, tostring(Role), IPAddress, IsAnonymousProxy, ISP, tokenMinutesAdded, tokenMinutesRemaining\n```"
---

