---
id: 7a5597de-7e99-470d-944f-acb163b9cb14
name: detect-malicious-use-of-msiexec
description: |
  This query was originally published in the threat analytics report, Msiexec abuse.
  Msiexec.exe is a Windows component that installs files with the .msi extension. These kinds of files are Windows installer packages, and are used by a wide array of legitimate software. However, malicious actors can re-purpose msiexec.exe for living-off-the-land attacks, where they use legitimate system binaries on the compromised device to perform attacks.
  The following query detects activity associated with misuse of msiexec.exe, particularly alongside mimikatz, a common credential dumper and privilege escalation tool.
  Reference - https://www.varonis.com/blog/what-is-mimikatz/
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
tactics:
  - Execution
  - Privilege escalation
  - Credential Access
query: "```kusto\n//Find possible download and execution using Msiexec\nDeviceProcessEvents\n| where Timestamp > ago(7d)\n//MSIExec\n| where FileName =~ \"msiexec.exe\" and \n//With domain in command line\n(ProcessCommandLine has \"http\" and ProcessCommandLine has \"return\")//Find PowerShell running files from the temp folder\n```"
---

