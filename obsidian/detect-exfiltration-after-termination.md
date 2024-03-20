---
id: 69ceaac7-5ea1-4a09-a8ce-b240210b8d2f
name: detect-exfiltration-after-termination
description: |
  This query can be used to explore any instances where a terminated individual (i.e. one who has an impending termination date but has not left the company) downloads a large number of files from a non-Domain network address.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceNetworkEvents
      - DeviceFileEvents
      - DeviceNetworkInfo
tactics:
  - Exfiltration
query: "```kusto\n// Look for any activity for terminated employee creating a DeviceNetworkEvents after they announced termination or resignation\nlet TermAccount = 'departing.employee'; //Enter the departing employee's username\nlet ReleaseTime = datetime(\"01/16/2022 00:00:00\"); //Enter the date the resignation or termination was announced\nDeviceNetworkEvents\n| where InitiatingProcessAccountName =~ TermAccount\n| where Timestamp  > ReleaseTime\n//| project Timestamp , DeviceName, InitiatingProcessAccountName\n| sort by Timestamp  desc\n| join \nDeviceFileEvents on InitiatingProcessAccountName\n| where FileName endswith \".docx\" or FileName endswith \".pptx\" or FileName endswith \".xlsx\" or FileName endswith \".pdf\"\n| join DeviceNetworkInfo on DeviceId\n| where ConnectedNetworks !contains '\"Category\":\"Domain\"'  //Looking for remote, non-domain networks\n| summarize TotalFiles=count() by bin(5Minutebin=Timestamp, 5m), InitiatingProcessAccountName\n|where TotalFiles >1000 // adjust accordingly\n| project TotalFiles,5Minutebin,InitiatingProcessAccountName\n```"
---

