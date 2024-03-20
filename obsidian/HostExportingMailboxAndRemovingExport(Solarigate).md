---
id: 1a6f998a-b9a4-4030-bd58-6606d66608f9
name: HostExportingMailboxAndRemovingExport[Solarigate]
description: |
  This hunting query looks for hosts exporting a mailbox from an on-prem Exchange server, followed by
  that same host removing the export within a short time window. This pattern has been observed by attackers
  when exfiltrating emails from a target environment. A Mailbox export is unlikely to be a common command run so look for
  activity from unexpected hosts and accounts.
  Reference: https://www.volexity.com/blog/2020/12/14/dark-halo-leverages-solarwinds-compromise-to-breach-organizations/
  Query insprired by Azure Sentinel detection https://github.com/Azure/Azure-Sentinel/blob/master/Hunting%20Queries/SecurityEvent/HostExportingMailboxAndRemovingExport.yaml
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
tactics:
  - Collection
query: "```kusto\n// Adjust the timeframe to change the window events need to occur within to alert\nlet timeframe = 1h;\nDeviceProcessEvents\n  | where FileName  in~ (\"powershell.exe\", \"cmd.exe\")\n  | where ProcessCommandLine  contains 'New-MailboxExportRequest'\n  | project-rename NewMailBoxExpCmd = ProcessCommandLine  \n  | summarize by DeviceName , timekey = bin(Timestamp, timeframe), NewMailBoxExpCmd, AccountName \n  | join kind=inner (DeviceProcessEvents\n  | where FileName in~ (\"powershell.exe\", \"cmd.exe\")\n  | where ProcessCommandLine contains 'Remove-MailboxExportRequest'\n  | project-rename RemoveMailBoxExpCmd = ProcessCommandLine\n  | summarize by DeviceName, timekey = bin(Timestamp, timeframe), RemoveMailBoxExpCmd, AccountName) on DeviceName, timekey, AccountName\n  | extend commands = pack_array(NewMailBoxExpCmd, RemoveMailBoxExpCmd)  \n  | summarize by timekey, DeviceName, tostring(commands), AccountName\n  | project-reorder timekey, DeviceName, AccountName, ['commands']\n  | extend HostCustomEntity = DeviceName, AccountCustomEntity = AccountName\n```"
---

