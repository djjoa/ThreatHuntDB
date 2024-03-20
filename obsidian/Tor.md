---
id: a0b19966-3b4d-45de-969c-ee5f1ef8c18a
name: Tor
description: |
  This query looks for Tor client, or for a common Tor plugin called Meek.
  We query for active Tor connections, but could have alternatively looked for active Tor runs (ProcessCreateEvents) or Tor downloads (DeviceFileEvents).
  To read more about this technique, see:.
  Tor: https://attack.mitre.org/wiki/Software/S0183#Techniques_Used.
  Meek plugin: https://attack.mitre.org/wiki/Software/S0175.
  Multi-hop proxy technique: https://attack.mitre.org/wiki/Technique/T1188.
  Tags: #Tor, #MultiHopProxy, #CnC.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceNetworkEvents
query: "```kusto\nDeviceNetworkEvents  \n| where Timestamp < ago(3d) and InitiatingProcessFileName in~ (\"tor.exe\", \"meek-client.exe\")\n// Returns MD5 hashes of files used by Tor, to enable you to block them.\n// We count how prevalent each file is (by machines) and show examples for some of them (up to 5 machine names per hash).\n| summarize MachineCount=dcount(DeviceName), MachineNames=makeset(DeviceName, 5) by InitiatingProcessMD5\n| order by MachineCount desc\n```"
---

