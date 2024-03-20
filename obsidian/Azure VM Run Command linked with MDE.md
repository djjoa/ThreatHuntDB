---
id: 55fbc363-6cc9-4201-bd68-d980b612082b
name: Azure VM Run Command linked with MDE
description: |
  'Identifies any Azure VM Run Command operations and links these operations with
  MDE host logging. Linking these two data sources provides hunting opportunities.
  Logging from AzureActivity provides the IP address and UPN of the account that
  invoked the command. Joining this with logging from MDE provides insights into
  what cmdlets were loaded by the command.'
requiredDataConnectors:
  - connectorId: AzureActivity
    dataTypes:
      - AzureActivity
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceFileEvents
      - DeviceEvents
tactics:
  - LateralMovement
  - CredentialAccess
relevantTechniques:
  - T1570
  - T1078.004
query: "```kusto\nAzureActivity\n// Isolate run command actions\n| where OperationNameValue == \"Microsoft.Compute/virtualMachines/runCommand/action\"\n// Confirm that the operation impacted a virtual machine\n| where Authorization has \"virtualMachines\"\n// Each runcommand operation consists of three events when successful, Started, Accepted (or Rejected), Successful (or Failed).\n| summarize StartTime=min(TimeGenerated), EndTime=max(TimeGenerated), max(CallerIpAddress), make_list(ActivityStatusValue) by CorrelationId, Authorization, Caller\n// Limit to Run Command executions that Succeeded\n| where list_ActivityStatusValue has \"Succeeded\"\n// Extract data from the Authorization field, allowing us to later extract the Caller (UPN) and CallerIpAddress\n| extend Authorization_d = parse_json(Authorization)\n| extend Scope = Authorization_d.scope\n| extend Scope_s = split(Scope, \"/\")\n| extend Subscription = tostring(Scope_s[2])\n| extend VirtualMachineName = tostring(Scope_s[-1])\n| project StartTime, EndTime, Subscription, VirtualMachineName, CorrelationId, Caller, CallerIpAddress=max_CallerIpAddress\n| join kind=leftouter (\n    DeviceFileEvents\n    | where InitiatingProcessFileName == \"RunCommandExtension.exe\"\n    | extend VirtualMachineName = tostring(split(DeviceName, \".\")[0])\n    | project VirtualMachineName, PowershellFileCreatedTimestamp=TimeGenerated, FileName, FileSize, InitiatingProcessAccountName, InitiatingProcessAccountDomain, InitiatingProcessFolderPath, InitiatingProcessId\n) on VirtualMachineName\n// We need to filter by time sadly, this is the only way to link events\n| where PowershellFileCreatedTimestamp between (StartTime .. EndTime)\n| project StartTime, EndTime, PowershellFileCreatedTimestamp, VirtualMachineName, Caller, CallerIpAddress, FileName, FileSize, InitiatingProcessId, InitiatingProcessAccountDomain, InitiatingProcessFolderPath\n| join kind=inner(\n    DeviceEvents\n    | extend VirtualMachineName = tostring(split(DeviceName, \".\")[0])\n    | where InitiatingProcessCommandLine has \"-File\"\n    | extend PowershellFileName = extract(@\"\\-File\\s(script[0-9]{1,9}\\.ps1)\", 1, InitiatingProcessCommandLine)\n    | extend PSCommand = tostring(parse_json(AdditionalFields).Command)\n    | order by TimeGenerated asc \n    | where PSCommand != PowershellFileName \n    | summarize PowershellExecStart=min(TimeGenerated), PowershellExecEnd=max(TimeGenerated), make_list(PSCommand) by PowershellFileName, InitiatingProcessCommandLine\n) on $left.FileName == $right.PowershellFileName\n| project StartTime, EndTime, PowershellFileCreatedTimestamp, PowershellExecStart, PowershellExecEnd, PowershellFileName, PowershellScriptCommands=list_PSCommand, Caller, CallerIpAddress, InitiatingProcessCommandLine, PowershellFileSize=FileSize, VirtualMachineName\n| order by StartTime asc \n| extend ScriptFingerprintHash = hash_sha256(tostring(PowershellScriptCommands))\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountCustomEntity
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPCustomEntity
---

