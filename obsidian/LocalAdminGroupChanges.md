---
id: dd2c4f48-b732-4a75-b2c4-b44bacc66d00
name: LocalAdminGroupChanges
description: |
  Author: alex verboon @alexverboon.
  Blogpost: https://www.verboon.info/2020/09/hunting-for-local-group-membership-changes.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - IdentityInfo
      - DeviceEvents
query: "```kusto\nlet ADAZUsers =  IdentityInfo \n| extend DirectoryDomain = AccountDomain \n| extend DirectoryAccount = AccountName \n| extend OnPremSid = AccountSID\n| distinct DirectoryDomain , DirectoryAccount , OnPremSid , AccountCloudSID, AccountUPN, GivenName, Surname;\n // check for any new created or modified local accounts \nlet NewUsers =  DeviceEvents\n| where ActionType contains \"UserAccountCreated\"  // or ActionType contains \"UserAccountModified\"\n| extend lUserAdded = AccountName\n| extend NewUserSID = AccountSid\n| extend laccountdomain = AccountDomain\n| distinct NewUserSID, lUserAdded,laccountdomain;\n// Check for any local group changes and enrich the data with the account name obtained from the previous query\nDeviceEvents \n| where ActionType == 'UserAccountAddedToLocalGroup' \n| extend AddedAccountSID = tostring(parse_json(AdditionalFields).MemberSid)\n| extend LocalGroup = AccountName\n| extend LocalGroupSID = AccountSid\n| extend Actor = trim(@\"[^\\w]+\",InitiatingProcessAccountName)\n// limit to local administrators group\n//  | where LocalGroupSID contains \"S-1-5-32-544\"\n| join kind= leftouter    (NewUsers)\non $left.AddedAccountSID == $right.NewUserSID\n| project Timestamp, DeviceName, LocalGroup,LocalGroupSID, AddedAccountSID, lUserAdded , Actor, ActionType , laccountdomain \n| join kind= leftouter        (ADAZUsers)\non $left.AddedAccountSID == $right.OnPremSid\n| extend UserAdded = iff(isnotempty(lUserAdded),strcat(laccountdomain,\"\\\\\", lUserAdded), strcat(DirectoryDomain,\"\\\\\", DirectoryAccount))\n| project Timestamp, DeviceName, LocalGroup,LocalGroupSID, AddedAccountSID, UserAdded , Actor, ActionType  \n| where DeviceName !contains Actor \n// Provide details on actors that added users\n// | summarize count()  by Actor \n// | join ADAZUsers\n// on $left.Actor == $right.DirectoryAccount \n// | render piechart \n```"
version: 1.0.0
---

