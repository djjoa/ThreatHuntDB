---
id: 1a9dfc1d-6dd2-42e5-81ef-fb90f3d96239
name: Webserver Executing Suspicious Applications
description: |
  This query looks for common webserver process names and identifies any processes launched using a scripting language (cmd, powershell, wscript, cscript), common initial profiling commands (net \ net1 \ whoami \ ping \ ipconfig),or admin commands (sc).  Note that seeing thisactivity doesn't immediately mean you have a breach, though you might consider  reviewing and honing the where clause to fit your specific web applications.
  Those who don't mind false positives should consider also adding database process names to this list as well (i.e. sqlservr.exe) to identify potential abuse of xp_cmdshell.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
tactics:
  - Execution
query: "```kusto\nDeviceProcessEvents\n| where Timestamp > ago(7d)\n| where InitiatingProcessFileName in~ ('w3wp.exe', 'httpd.exe') // 'sqlservr.exe')\n| where FileName in~ ('cmd.exe', 'powershell.exe', 'cscript.exe', 'wscript.exe', 'net.exe', 'net1.exe', 'ping.exe', 'whoami.exe')\n| summarize instances = count() by ProcessCommandLine, FolderPath, DeviceName, DeviceId \n| order by instances asc\n```"
---

