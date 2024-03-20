---
id: 4c290208-c36d-4e57-8d6d-f7e790dc0d3f
name: Qakbot discovery activies
description: |
  Use this query to locate injected processes launching discovery activity. Qakbot has been observed leading to ransomware in numerous instances.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
tactics:
  - Ransomware
query: "```kusto\nDeviceProcessEvents \n| where InitiatingProcessFileName in~('mobsync.exe','explorer.exe')\n| where (FileName =~ 'net.exe' and InitiatingProcessCommandLine has_all('view','/all'))\n     or (FileName =~ 'whoami.exe' and InitiatingProcessCommandLine has '/all')\n     or (FileName =~ 'nslookup.exe' and InitiatingProcessCommandLine has_all('querytype=ALL','timeout=10'))\n     or (FileName =~ 'netstat.exe' and InitiatingProcessCommandLine has '-nao')\n     or (FileName =~ 'arp.exe' and InitiatingProcessCommandLine has '-a')\n     or (FileName =~ 'ping.exe' and InitiatingProcessCommandLine has '-t' and InitiatingProcessCommandLine endswith '127.0.0.1')\n| summarize DiscoveryCommands = dcount(InitiatingProcessCommandLine), make_set(InitiatingProcessFileName), make_set(FileName), make_set(InitiatingProcessCommandLine) by DeviceId, bin(Timestamp, 5m)   \n| where DiscoveryCommands >= 3\n```"
---

