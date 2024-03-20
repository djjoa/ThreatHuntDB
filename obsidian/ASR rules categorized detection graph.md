---
id: 4a7bf574-fe5f-4168-97e7-5a8aa19a5eed
name: ASR rules categorized detection graph
description: "This query offers daily categorization of ASR rules, helping SOC analysts monitor specific categories like office-related activities or WMI among the 16 rules. \nIt aids in tracking detection rates and organizational trends.\n"
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceEvents
tactics: []
query: "```kusto\nDeviceEvents\n| where Timestamp > ago(7d)\n| where ActionType startswith \"asr\"\n| extend Parsed = parse_json(AdditionalFields)\n// | where Parsed.IsAudit == \"true\" \n| where Parsed.IsAudit == \"false\" \n| summarize Email = countif(ActionType in (\"AsrExecutableEmailContentBlocked\", \"AsrOfficeCommAppChildProcessBlocked\")),\n            Script = countif(ActionType in (\"AsrObfuscatedScriptBlocked\", \"AsrScriptExecutableDownloadBlocked\")),\n            WMI = countif(ActionType in (\"AsrPersistenceThroughWmiBlocked\", \"AsrPsexecWmiChildProcessBlocked\")),\n            OfficeApp = countif(ActionType in (\"AsrOfficeChildProcessBlocked\", \"AsrOfficeMacroWin32ApiCallsBlocked\", \"AsrExecutableOfficeContentBlocked\", \"AsrOfficeProcessInjectionBlocked\")),\n            3rdPartyApp = countif(ActionType == \"AsrAdobeReaderChildProcessBlocked\"),\n            WindowsCredentials = countif(ActionType == \"AsrLsassCredentialTheftBlocked\"),\n            PolymorphicThreats = countif(ActionType in (\"AsrUntrustedExecutableBlocked\", \"AsrUntrustedUsbProcessBlocked\", \"AsrRansomwareBlocked\", \"AsrVulnerableSignedDriverBlocked\")) by bin(Timestamp, 1d)\n| render columnchart\n```"
---

