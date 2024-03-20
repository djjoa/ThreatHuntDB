---
id: a5649d8b-e54b-4e2b-925a-106bf838d69c
name: Accessibility Features
description: |
  This query looks for persistence or priviledge escalation done using Windows Accessibility features.
  It covers some of the techniques that could be used to utilize these features for malicious purposes,.
  Including attaching a debugger using a registry config or overwriting these files.
  Note: some developers might use such hacks for all sort of troubleshooting and testing purposes,.
  But this better be prohibited, as it allows any account with access to the machine to run processes as SYSTEM.
  Read more here: https://attack.mitre.org/wiki/Technique/T1015.
  Tags: #AccessibilityFeatures, #StickyKeys, #ImageFileExecutionOptions, #Debugger, #PriviledgeEscalation, #Persistence.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceRegistryEvents
      - DeviceFileEvents
      - DeviceProcessEvents
query: "```kusto\nlet minTime = ago(7d);\nlet accessibilityProcessNames = dynamic([\"utilman.exe\",\"osk.exe\",\"magnify.exe\",\"narrator.exe\",\"displayswitch.exe\",\"atbroker.exe\",\"sethc.exe\", \"helppane.exe\"]);\n// Query for debuggers attached using a Registry setting to the accessibility processes\nlet attachedDebugger =\n    DeviceRegistryEvents\n    | where Timestamp > minTime\n    and RegistryKey startswith @\"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\\"\n    and RegistryValueName =~ \"debugger\"\n\t// Parse the debugged process name from the registry key\n    | parse RegistryKey with @\"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\\" FileName\n    | where FileName in~ (accessibilityProcessNames) and isnotempty(RegistryValueData)\n    | project Technique=\"AttachedDebugger\", FileName, AttachedDebuggerCommandline=RegistryValueData, InitiatingProcessCommandLine, Timestamp, DeviceName;\n// Query for overwrites of the accessibility files\nlet fileOverwiteOfAccessibilityFiles =\n    DeviceFileEvents\n    | where Timestamp > minTime\n        and FileName in~ (accessibilityProcessNames)\n        and FolderPath contains @\"Windows\\System32\" \n    | project Technique=\"OverwriteFile\", Timestamp, DeviceName, FileName, SHA1, InitiatingProcessCommandLine;\n// Query for unexpected hashes of processes with names matching the accessibility processes.\n// Specifically, query for hashes matching cmd.exe and powershell.exe, as these MS-signed general-purpose consoles are often used with this technique.\nlet executedProcessIsPowershellOrCmd =\n    DeviceProcessEvents \n    | project Technique=\"PreviousOverwriteFile\", Timestamp, DeviceName, FileName, SHA1 \n    | where Timestamp > minTime\n    | where FileName in~ (accessibilityProcessNames)\n    | join kind=leftsemi(\n        DeviceProcessEvents  \n        | where Timestamp > ago(14d) and (FileName =~ \"cmd.exe\" or FileName =~ \"powershell.exe\")\n        | summarize MachinesCount = dcount(DeviceName) by SHA1  \n        | where MachinesCount > 5\n        | project SHA1\n    ) on SHA1;\n// Union all results together. \n// An outer union is used because the schemas are a bit different between the tables - and we want to get the superset of all tables combined.\nattachedDebugger\n| union kind=outer fileOverwiteOfAccessibilityFiles\n| union kind=outer executedProcessIsPowershellOrCmd\n```"
---

