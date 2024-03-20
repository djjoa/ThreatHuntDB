---
id: 8b8be25f-1bc0-4d57-81a7-76ef97f1d64f
name: confluence-weblogic-targeted
description: |
  This query was originally published in the threat analytics report, Confluence and WebLogic abuse.
  2019 has seen several seemingly related campaigns targeting Atlassian Confluence Server and Oracle WebLogic Server. Although these campaigns use different implants and delivery methods, they consistently use the same infrastructure, and exploit the same vulnerabilities.
  The campaigns have specifically targeted:
  1. CVE-2019-3396 - Software update
  2. CVE-2019-2725 - Software update
  The following query detects activity broadly associated with these campaigns.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
tactics:
  - Vulnerability
query: "```kusto\nDeviceProcessEvents\n| where Timestamp >= ago(7d)\n| where \n// \"Grandparent\" process is Oracle WebLogic or some process loading Confluence\nInitiatingProcessParentFileName == \"beasvc.exe\" or \nInitiatingProcessFileName == \"beasvc.exe\" \nor InitiatingProcessCommandLine contains \"//confluence\"\n// Calculate for Base64 in Commandline\n| extend Caps = countof(ProcessCommandLine, \"[A-Z]\", \"regex\"), \nTotal = countof(ProcessCommandLine, \".\", \"regex\")\n| extend Ratio = todouble(Caps) / todouble(Total) \n| where\n(\n    FileName in~ (\"powershell.exe\" , \"powershell_ise.exe\") // PowerShell is spawned\n    // Omit known clean processes\n    and ProcessCommandLine !startswith \"POWERSHELL.EXE  -C \\\"GET-WMIOBJECT -COMPUTERNAME\"\n    and ProcessCommandLine !contains \"ApplicationNo\"\n    and ProcessCommandLine !contains \"CustomerGroup\"\n    and ProcessCommandLine !contains \"Cosmos\"\n    and ProcessCommandLine !contains \"Unrestricted\"\n    and\n    (\n        ProcessCommandLine contains \"$\" // PowerShell variable declaration\n        or ProcessCommandLine contains \"-e \" // Alias for \"-EncodedCommand\" parameter\n        or ProcessCommandLine contains \"encodedcommand\"\n        or ProcessCommandLine contains \"wget\"\n        //or ( Ratio > 0.4 and Ratio < 1.0) // Presence of Base64 strings\n    )\n)\nor\n(\n    FileName =~ \"cmd.exe\" // cmd.exe is spawned\n    and ProcessCommandLine contains \"@echo\" and \n    ProcessCommandLine contains \">\" // Echoing commands into a file\n)\nor\n(\n    FileName =~ \"certutil.exe\" // CertUtil.exe abuse\n    and ProcessCommandLine contains \"-split\" \n    // the \"-split\" parameter is required to write files to the disk\n)\n| project\n       Timestamp,\n       InitiatingProcessCreationTime ,\n       DeviceId ,\n       Grandparent_PID = InitiatingProcessParentId,\n       Grandparent = InitiatingProcessParentFileName,\n       Parent_Account = InitiatingProcessAccountName,\n       Parent_PID = InitiatingProcessId,\n       Parent = InitiatingProcessFileName ,\n       Parent_Commandline = InitiatingProcessCommandLine,\n       Child_PID = ProcessId,\n       Child = FileName ,\n       Child_Commandline = ProcessCommandLine\n```"
---

