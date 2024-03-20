---
id: 2458e226-76e6-458c-8bf7-8766cc993b82
name: Bitsadmin Activity
description: "Background Intelligent Transfer Service (BITS) is a way to reliably download files from webservers or SMB servers. \nThis service is commonly used for legitimate purposes, but can also be used as part of a malware downloader. \nAdditionally, bitsadmin can be used to upload files and therefore can be used for data exfiltration. This\nquery will identify use of bitsadmin.exe for either purpose and will identify directionality file transfer\ndirectionality.\n"
tactics:
  - Persistence
  - CommandAndControl
  - Exfiltration
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
query: "```kusto\nDeviceProcessEvents\n| where \n    (FileName =~ \"bitsadmin.exe\" or column_ifexists('ProcessVersionInfoOriginalFileName','ColumnNotAvailable') =~ 'bitsadmin.exe')\n    and ProcessCommandLine has_any ('/Transfer','/AddFile', '/AddFileSet','/AddFileWithRanges')\n| extend \n    ParsedCommandLine = parse_command_line(ProcessCommandLine,'windows')\n| extend     \n    RemoteUrl = tostring(ParsedCommandLine[-2]),\n    LocalFile= tostring(ParsedCommandLine[-1]),\n    Direction = iff(ProcessCommandLine has \"/Upload\", 'Upload', 'Download')\n| project-reorder \n    Timestamp,\n    DeviceId,\n    DeviceName,\n    Direction,\n    RemoteUrl,\n    LocalFile,\n    InitiatingProcessFolderPath,\n    InitiatingProcessAccountDomain,\n    InitiatingProcessAccountName,\n    InitiatingProcessSHA256,\n    ProcessCommandLine\n```"
---

