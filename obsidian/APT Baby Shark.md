---
id: 26721b80-a9b7-4594-9b0f-ec21e5da1bc2
name: APT Baby Shark
description: |
  Original Sigma Rule: https://github.com/Neo23x0/sigma/blob/master/rules/apt/apt_babyshark.yml.
  Questions via Twitter: @janvonkirchheim.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
query: "```kusto\nDeviceProcessEvents \n| where Timestamp > ago(7d)\n| where ProcessCommandLine =~ @\"reg query \"\"HKEY_CURRENT_USER\\Software\\Microsoft\\Terminal Server Client\\Default\"\"\" \n     or ProcessCommandLine startswith \"powershell.exe mshta.exe http\"\n     or ProcessCommandLine =~ \"cmd.exe /c taskkill /im cmd.exe\"\n| top 100 by Timestamp desc\n```"
---

