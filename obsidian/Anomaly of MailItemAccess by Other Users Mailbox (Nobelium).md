---
id: 6a927d9a-66c3-4491-815d-a31d4bbb2948
name: Anomaly of MailItemAccess by Other Users Mailbox [Nobelium]
description: |
  This query looks for users accessing multiple other users' mailboxes, or accessing multiple folders in another user's mailbox.
  This query is inspired by an Azure Sentinel detection.
  Reference - https://github.com/Azure/Azure-Sentinel/blob/master/Hunting%20Queries/OfficeActivity/AnomolousUserAccessingOtherUsersMailbox.yaml
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - CloudAppEvents
tactics:
  - Collection
tags:
  - Nobelium
query: "```kusto\n// Adjust this value to exclude historical activity as known good\nlet LookBack = 30d;\n// Adjust this value to change hunting timeframe\nlet TimeFrame = 14d;\n// Adjust this value to alter how many mailbox (other than their own) a user needs to access before being included in results\nlet UserThreshold = 1;\n// Adjust this value to alter how many mailbox folders in other's email accounts a users needs to access before being included in results.\nlet FolderThreshold = 5;\nlet relevantMailItems = materialize (\n    CloudAppEvents\n    | where Timestamp > ago(LookBack)\n    | where ActionType == \"MailItemsAccessed\"\n    | where RawEventData['ResultStatus'] == \"Succeeded\"\n    | extend UserId = tostring(RawEventData['UserId'])\n    | extend MailboxOwnerUPN = tostring(RawEventData['MailboxOwnerUPN'])\n    | where tolower(UserId) != tolower(MailboxOwnerUPN)\n    | extend Folders = RawEventData['Folders']\n    | where isnotempty(Folders)\n    | mv-expand parse_json(Folders)\n    | extend foldersPath = tostring(Folders.Path)  \n    | where isnotempty(foldersPath)\n    | extend ClientInfoString = RawEventData['ClientInfoString']\n    | extend MailBoxGuid = RawEventData['MailboxGuid']\n    | extend ClientIP = iif(IPAddress startswith \"[\", extract(\"\\\\[([^\\\\]]*)\", 1, IPAddress), IPAddress)\n    | project Timestamp, ClientIP, UserId, MailboxOwnerUPN, tostring(ClientInfoString), foldersPath, tostring(MailBoxGuid)    \n);\nlet relevantMailItemsBaseLine = \n    relevantMailItems\n    | where Timestamp between(ago(LookBack) ..  ago(TimeFrame))    \n    | distinct MailboxOwnerUPN, UserId;\nlet relevantMailItemsHunting = \n    relevantMailItems\n    | where Timestamp between(ago(TimeFrame) .. now())\n    | distinct ClientIP, UserId, MailboxOwnerUPN, ClientInfoString, foldersPath, MailBoxGuid; \nrelevantMailItemsBaseLine \n    | join kind=rightanti relevantMailItemsHunting\n    on MailboxOwnerUPN, UserId\n    | summarize FolderCount = dcount(tostring(foldersPath)),\n                UserCount = dcount(MailBoxGuid),\n                foldersPathSet = make_set(foldersPath),\n                ClientInfoStringSet = make_set(ClientInfoString), \n                ClientIPSet = make_set(ClientIP),\n                MailBoxGuidSet = make_set(MailBoxGuid),\n                MailboxOwnerUPNSet = make_set(MailboxOwnerUPN)\n            by UserId\n    | where UserCount > UserThreshold or FolderCount > FolderThreshold\n    | extend Reason = case( \n                            UserCount > UserThreshold and FolderCount > FolderThreshold, \"Both User and Folder Threshold Exceeded\",\n                            FolderCount > FolderThreshold and UserCount < UserThreshold, \"Folder Count Threshold Exceeded\",\n                            \"User Threshold Exceeded\"\n                            )\n    | sort by UserCount desc\n```"
---

