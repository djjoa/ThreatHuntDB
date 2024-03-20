---
id: 26534fba-d2bf-449a-af40-c287c2874668
name: Imminent Ransomware
description: |
  Directly prior to deploying Macaw ransomware in an organization, the attacker will run several commands designed to disable security tools and system recovery tools.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
tactics:
  - Ransomware
query: "```kusto\nDeviceProcessEvents \n// Pivot on specific commands \n| where ProcessCommandLine has_any(\"-ExclusionPath\", \"Set-MpPreference\", \"advfirewall\", \"-ExclusionExtension\", \n\"-EnableControlledFolderAccess\", \"windefend\", \"onstart\", \"bcdedit\", \"Startup\") \n// Making list of found commands \n| summarize ProcessCommandLine = make_set(ProcessCommandLine) by DeviceId, bin(Timestamp, 6h) \n// Extending columns for later aggregration, based on TTP \n| extend StartUpExclusionPath = iff(ProcessCommandLine has_all(\"-ExclusionPath\", \"Startup\"), 1, 0) \n| extend DefenderTamp = iff(ProcessCommandLine has \"Set-MpPreference\" \nand ProcessCommandLine has_any( \n\"-SevereThreatDefaultAction 6\" \n\"-HighThreatDefaultAction 6\", \n\"-ModerateThreatDefaultAction 6\", \n\"-LowThreatDefaultAction 6\" \n\"-ScanScheduleDay 8\"), 1, 0) \n| extend NetshFirewallTampering = iff(ProcessCommandLine has_all( \"netsh\", \"advfirewall\", \"allprofiles state off\"), 1, 0) \n| extend BatExclusion = iff(ProcessCommandLine has_all(\"-ExclusionExtension\", \".bat\"), 1, 0) \n| extend ExeExclusion = iff(ProcessCommandLine has_all(\"-ExclusionExtension\", \".exe\"), 1, 0) \n| extend DisableControlledFolderAccess = iff(ProcessCommandLine has_all(\"-EnableControlledFolderAccess\", \"Disabled\"), 1, 0) \n| extend ScDeleteDefend = iff(ProcessCommandLine has_all(\"sc\", \"delete\", \"windefend\"), 1, 0) \n| extend BootTampering = iff(ProcessCommandLine has_all(\"bcdedit\", \"default\") and ProcessCommandLine has_any (\"recoveryenabled No\", \"bootstatuspolicy ignoreallfailures\"), 1, 0) \n| extend SchTasks = iff(ProcessCommandLine has_all(\"/sc\", \"onstart\", \"system\", \"/create\", \"/delay\"), 1, 0) \n// Summarizing found commands \n| summarize by NetshFirewallTampering ,BatExclusion, ExeExclusion, DisableControlledFolderAccess, ScDeleteDefend, SchTasks, BootTampering, DefenderTamp, StartUpExclusionPath, DeviceId, Timestamp \n// Adding up each piece of evidence \n| extend EvidenceCount = NetshFirewallTampering + BatExclusion + ExeExclusion + DisableControlledFolderAccess + ScDeleteDefend + SchTasks + BootTampering + DefenderTamp + StartUpExclusionPath \n| where EvidenceCount > 4 \n```"
---

