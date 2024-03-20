---
id: 2fe0bb17-2e2e-407f-b82e-baf16161196a
name: Device uptime calculation
description: |
  This query calculates device uptime based on periodic DeviceInfo which is recorded every 15 minutes regardless of device's network connectivity and uploaded once device gets online. If its interval is over 16 minutes, we can consider device is turned off.Calculated uptime may include up to 30 minutes gap. Devices may be turned on up to 15 minutes earlier than the "timestamp", and may be turned off up to 15 minutes later than the "LastTimestamp".  When the single independent DeviceInfo without any sequential DeviceInfo within 16 minutes before or after is recorded, "DurationAtLeast" will be displayed as "00.00:00:00".
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceInfo
tactics:
  - Initial access
  - Persistence
  - Command and control
query: "```kusto\nDeviceInfo \n| order by DeviceId, Timestamp desc\n| extend FinalSignal = (prev(DeviceId,1) != DeviceId) or (prev(LoggedOnUsers,1) != LoggedOnUsers) or (prev(Timestamp,1,now(1d)) - Timestamp > 16m)\n| extend StartSignal = (next(DeviceId,1) != DeviceId) or (next(LoggedOnUsers,1) != LoggedOnUsers) or (Timestamp - next(Timestamp,1,0) > 16m)\n| where FinalSignal or StartSignal\n| extend LastTimestamp=iff(FinalSignal,Timestamp,prev(Timestamp,1))\n| where StartSignal\n| extend ParsedFields=parse_json(LoggedOnUsers)[0]\n| extend DurationAtLeast= format_timespan(LastTimestamp-Timestamp,'dd.hh:mm:ss')\n| project Timestamp,LastTimestamp,DurationAtLeast,DeviceName,DomainName=ParsedFields.DomainName,UserName=ParsedFields.UserName\n```"
---

