---
id: 62bc4944-46dd-4c2f-ba04-72837bbfec3f
name: detect-prifou-pua
description: |
  This query was originally published in the threat analytics report, ironSource PUA & unwanted apps impact millions.
  IronSource provides software bundling tools for many popular legitimate apps, such as FileZilla. However, some of ironSource's bundling tools are considered PUA, because they exhibit potentially unwanted behavior. One component of these tools, detected by Microsoft as Prifou, silently transmits system information from the user. It also installs an outdated version of Chromium browser with various browser extensions, resets the user's home page, changes their search engine settings, and forces Chromium and itself to launch at startup.
  The following query can be used to locate unique command-line strings used by ironSource bundlers to launch Prifou, as well as commands used by Prifou to install Chromium.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceFileEvents
      - DeviceProcessEvents
tactics:
  - Persistence
  - Malware, component
query: "```kusto\nunion DeviceFileEvents, DeviceProcessEvents \n| where Timestamp > ago(7d)\n// Prifou launched by ironSource bundler\n| where ProcessCommandLine has \"/mhp \" and ProcessCommandLine has \"/mnt \" \nand ProcessCommandLine has \"/mds \"\n// InstallCore launch commands\nor (ProcessCommandLine has \"/mnl\" and ProcessCommandLine has \"rsf\")\n// Chromium installation\nor ProcessCommandLine has \"bundlename=chromium\"\nor FileName == \"prefjsonfn.txt\"\n| project SHA1, ProcessCommandLine, FileName, InitiatingProcessFileName,\nInitiatingProcessCommandLine, InitiatingProcessSHA1\n```"
---

