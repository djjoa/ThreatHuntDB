---
id: 726085be-fa36-4b0f-991a-b5bc8fe53d87
name: detect-mailsniper
description: |
  This query was originally published in the threat analytics report, MailSniper Exchange attack tool.
  MailSniper is a tool that targets Microsoft Exchange Server. The core function is to connect to Exchange Server and search through emails. In support of this, it can perform reconnaissance, collection, exfiltration, and credential theft. MailSniper is used both by red teams running penetration tests, and by malicious actors.
  Microsoft Defender Security Center may record the following alerts during and after an attack:
  1. Global mail search on Exchange using MailSniper
  2. Exchange mailbox or mail folder search using MailSniper
  3. Enumeration of Active Directory usernames using MailSniper
  4. Enumeration of the Exchange GAL using MailSniper
  5. Access to Exchange inboxes using MailSniper
  6. Password spraying using MailSniper
  7. Enumeration of domains and user accounts using MailSniper
  The following query detects activity commonly associated with attacks run with MailSniper.
  Reference - https://github.com/dafthack/MailSniper
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
      - DeviceNetworkEvents
tactics:
  - Initial access
  - Credential Access
  - Collection
  - Exfiltration
query: "```kusto\nlet dateRange = ago(10d);\n//\nlet whoamiProcess = DeviceProcessEvents\n| where ProcessCreationTime >= dateRange\n| where FileName =~ 'whoami.exe' and InitiatingProcessParentFileName =~ 'powershell.exe'\n| project DeviceId, whoamiTime = ProcessCreationTime, whoamiProcessName = FileName, \nwhoamiParentName = InitiatingProcessParentFileName, whoamiParentPID = InitiatingProcessParentId;\n//\nlet netProcess = DeviceProcessEvents \n| where ProcessCreationTime >= dateRange\n| where FileName =~ 'net.exe' and InitiatingProcessParentFileName =~ 'powershell.exe'\n| project DeviceId, netTime = ProcessCreationTime, ProcessCreationTime = FileName, \nnetParentName = InitiatingProcessParentFileName, netParentPID = InitiatingProcessParentId;\n//\nlet mailServerEvents = DeviceNetworkEvents\n| where Timestamp >= dateRange\n| where InitiatingProcessFileName =~ 'powershell.exe'\n| where RemoteUrl contains 'onmicrosoft.com'\nor RemoteUrl contains 'outlook.com'\n| project DeviceId, mailTime = Timestamp, mailProcessName = InitiatingProcessFileName, \nmailPID = InitiatingProcessId;\n//\nmailServerEvents\n| join netProcess on DeviceId \n| where netParentPID == mailPID and netParentName == mailProcessName \n| join whoamiProcess on DeviceId \n| where whoamiParentPID == mailPID and whoamiParentName == mailProcessName \n| where netTime < mailTime + 4h and netTime > mailTime - 4h\n| where whoamiTime < mailTime + 4h and whoamiTime > mailTime - 4h\n| project DeviceId, EstimatedIncidentTime = mailTime, ProcessName = mailProcessName, \nProcessID = mailPID\n```"
---

