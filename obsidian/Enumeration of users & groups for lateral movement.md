---
id: dde6f931-559e-4e21-9409-6286de59771e
name: Enumeration of users & groups for lateral movement
description: |
  The query finds attempts to list users or groups using Net commands.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
query: "```kusto\nDeviceProcessEvents \n| where Timestamp > ago(14d) \n| where FileName == 'net.exe' and AccountName != \"\" and ProcessCommandLine !contains '\\\\'  and ProcessCommandLine !contains '/add' \n| where (ProcessCommandLine contains ' user ' or ProcessCommandLine contains ' group ') and (ProcessCommandLine contains ' /do' or ProcessCommandLine contains ' /domain') \n| extend Target = extract(\"(?i)[user|group] (\\\"*[a-zA-Z0-9-_ ]+\\\"*)\", 1, ProcessCommandLine) | filter Target  != '' \n| project AccountName, Target, ProcessCommandLine, DeviceName, Timestamp  \n| sort by AccountName, Target\n```"
---

