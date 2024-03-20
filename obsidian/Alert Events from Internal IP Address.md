---
id: f936ddfa-58e3-4db1-834b-fb50e8bd55c5
name: Alert Events from Internal IP Address
description: |
  Determines DeviceId from internal IP address and outputs all alerts in events table associated to the DeviceId.
  Example use case is Firewall determines Internal IP with suspicious network activity. Query WDATP based on date/time and Internal IP and see associated alerts for the endpoint.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceNetworkInfo
      - AlertEvidence
      - AlertInfo
query: "```kusto\nlet PivotTime = datetime(2021-01-02 20:57:02); //Fill out time\nlet TimeRangeStart = PivotTime-15m; // 15 Minutes Prior to Pivot Time\nlet TimeRangeEnd = PivotTime+15m; // 15 Minutes After Pivot Time\nlet IPAddress = \"172.16.40.8\";  // internal IP address to search\n// Locate DeviceIds associated with IP\nlet FindDeviceIdbyIP = DeviceNetworkInfo\n| where Timestamp between ((TimeRangeStart) ..TimeRangeEnd) \n\tand IPAddresses contains strcat(\"\\\"\", IPAddress, \"\\\"\") \n\tand NetworkAdapterStatus == \"Up\"\n| project DeviceName, DeviceId, Timestamp, IPAddresses;\n// Query Alerts matching DeviceIds\nFindDeviceIdbyIP \n| join kind=rightsemi AlertEvidence on DeviceId\n| join AlertInfo on AlertId\n// Summarizes alerts by AlertId with min and max event times\n| summarize Title=any(Title), min(Timestamp), max(Timestamp), DeviceName=any(DeviceName) by AlertId\n```"
---

