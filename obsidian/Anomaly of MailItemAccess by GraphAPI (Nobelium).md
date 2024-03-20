---
id: 5cb88a85-f9d9-48eb-a23a-55960f0f8ad4
name: Anomaly of MailItemAccess by GraphAPI [Nobelium]
description: |
  This query looks for anomalies in mail item access events made by Graph API. It uses standard deviation to determine if the number of events is anomalous. The query returns all clientIDs where the amount of mail sent per day was larger than value given by the formula, 'average + STDThreshold(2.5)*(standard deviation)'.
  See The MailItemsAccessed mailbox auditing action.
  Reference - https://docs.microsoft.com/microsoft-365/compliance/mailitemsaccessed-forensics-investigations?view=o365-worldwide#the-mailitemsaccessed-mailbox-auditing-action
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - CloudAppEvents
tactics:
  - Exfiltration
tags:
  - Nobelium
query: "```kusto\nlet starttime = 30d;\nlet STDThreshold = 2.5;\nlet allMailAccsessByGraphAPI = CloudAppEvents\n| where   ActionType == \"MailItemsAccessed\"\n| where Timestamp between (startofday(ago(starttime))..now())\n| where isnotempty(RawEventData['ClientAppId'] ) and RawEventData['AppId'] has \"00000003-0000-0000-c000-000000000000\"\n| extend ClientAppId = tostring(RawEventData['ClientAppId'])\n| extend OperationCount = toint(RawEventData['OperationCount'])\n| project Timestamp,OperationCount , ClientAppId;\nlet calculateNumberOfMailPerDay = allMailAccsessByGraphAPI\n| summarize NumberOfMailPerDay =sum(toint(OperationCount)) by ClientAppId,format_datetime(Timestamp, 'y-M-d');\nlet calculteAvgAndStdev=calculateNumberOfMailPerDay\n| summarize avg=avg(NumberOfMailPerDay),stev=stdev(NumberOfMailPerDay) by ClientAppId;\ncalculteAvgAndStdev  | join calculateNumberOfMailPerDay on ClientAppId\n| sort by ClientAppId\n|  where NumberOfMailPerDay > avg + STDThreshold * stev\n| project ClientAppId,Timestamp,NumberOfMailPerDay,avg,stev \n```"
---

