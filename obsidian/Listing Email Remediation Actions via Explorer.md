---
id: 99713387-9d61-49eb-8edc-f51153d8bb01
name: Listing Email Remediation Actions via Explorer
description: "- Track each cases with Network Message ID\n- Sort the users who got a number of actions \n- e.g. Soft Delete, Hard Delete, Move to junk folder, Move to deleted items \n"
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - EmailEvents
tactics: []
query: "```kusto\nEmailEvents\n| where Timestamp > ago(30d)\n| where LatestDeliveryAction in (\"Hard delete\", \"Soft delete\", \"Moved to junk folder\", \"Moved to deleted items\")\n| summarize HardDelete_NetworkID = make_list_if(strcat(NetworkMessageId, @\"\\\", Timestamp,@\"\\\", Subject), LatestDeliveryAction == \"Hard delete\"),  \n            SoftDelete_NetworkID = make_list_if(strcat(NetworkMessageId, @\"\\\", Timestamp,@\"\\\", Subject), LatestDeliveryAction == \"Soft delete\"),\n            MoveToJunk_NetworkID = make_list_if(strcat(NetworkMessageId, @\"\\\", Timestamp,@\"\\\", Subject), LatestDeliveryAction == \"Moved to junk folder\"),\n            MoveToDelete_NetworkID = make_list_if(strcat(NetworkMessageId, @\"\\\", Timestamp,@\"\\\", Subject), LatestDeliveryAction == \"Moved to deleted items\") by RecipientEmailAddress\n| extend HardDelete_case = array_length(HardDelete_NetworkID)\n| extend SoftDelete_case = array_length(SoftDelete_NetworkID)\n| extend MoveToJunk_case = array_length(MoveToJunk_NetworkID)\n| extend MoveToDelete_case = array_length(MoveToDelete_NetworkID)\n| extend Sum_case = HardDelete_case + SoftDelete_case + MoveToJunk_case + MoveToDelete_case\n| project RecipientEmailAddress, Sum_case, HardDelete_case, SoftDelete_case, MoveToJunk_case, MoveToDelete_case, HardDelete_NetworkID, SoftDelete_NetworkID, MoveToJunk_NetworkID, MoveToDelete_NetworkID\n| order by Sum_case desc \n```"
---

