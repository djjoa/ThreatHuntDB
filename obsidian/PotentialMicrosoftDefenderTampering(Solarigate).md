---
id: 3f16e2c2-c0ba-4286-be9a-f22d001d2de7
name: PotentialMicrosoftDefenderTampering[Solarigate]
description: |
  Identifies potential service tampering related to Microsoft Defender services.
  Query insprired by Azure Sentinel detection https://github.com/Azure/Azure-Sentinel/blob/master/Hunting%20Queries/MultipleDataSources/PotentialMicrosoftDefenderTampering.yaml
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
tactics:
  - Defense evasion
query: "```kusto\nlet includeProc = dynamic([\"sc.exe\",\"net1.exe\",\"net.exe\", \"taskkill.exe\", \"cmd.exe\", \"powershell.exe\"]);\nlet action = dynamic([\"stop\",\"disable\", \"delete\"]);\nlet service1 = dynamic(['sense', 'windefend', 'mssecflt']);\nlet service2 = dynamic(['sense', 'windefend', 'mssecflt', 'healthservice']);\nlet params1 = dynamic([\"-DisableRealtimeMonitoring\", \"-DisableBehaviorMonitoring\" ,\"-DisableIOAVProtection\"]);\nlet params2 = dynamic([\"sgrmbroker.exe\", \"mssense.exe\"]);\nlet regparams1 = dynamic(['reg add \"HKLM\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows Defender\"', 'reg add \"HKLM\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows Advanced Threat Protection\"']);\nlet regparams2 = dynamic(['ForceDefenderPassiveMode', 'DisableAntiSpyware']);\nlet regparams3 = dynamic(['sense', 'windefend']);\nlet regparams4 = dynamic(['demand', 'disabled']);\nlet timeframe = 1d;\n DeviceProcessEvents\n  | where Timestamp >= ago(timeframe)\n  | where InitiatingProcessFileName in~ (includeProc)\n  | where (InitiatingProcessCommandLine has_any(action) and InitiatingProcessCommandLine has_any (service2) and InitiatingProcessParentFileName != 'cscript.exe')\n  or (InitiatingProcessCommandLine has_any (params1) and InitiatingProcessCommandLine has 'Set-MpPreference' and InitiatingProcessCommandLine has '$true') \n  or (InitiatingProcessCommandLine has_any (params2) and InitiatingProcessCommandLine has \"/IM\") \n  or (InitiatingProcessCommandLine has_any (regparams1) and InitiatingProcessCommandLine has_any (regparams2) and InitiatingProcessCommandLine has '/d 1') \n  or (InitiatingProcessCommandLine has_any(\"start\") and InitiatingProcessCommandLine has \"config\" and InitiatingProcessCommandLine has_any (regparams3) and InitiatingProcessCommandLine has_any (regparams4))\n  | extend Account = iff(isnotempty(InitiatingProcessAccountUpn), InitiatingProcessAccountUpn, InitiatingProcessAccountName), Computer = DeviceName\n  | project Timestamp, Computer, Account, AccountDomain, ProcessName = InitiatingProcessFileName, ProcessNameFullPath = FolderPath, Activity = ActionType, CommandLine = InitiatingProcessCommandLine, InitiatingProcessParentFileName\n```"
---

