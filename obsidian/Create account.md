---
id: ae177dc6-a3ba-474d-87a9-28ff7efb7b21
name: Create account
description: |
  User accounts may be created to achieve persistence on a machine.
  Read more here: https://attack.mitre.org/wiki/Technique/T1136.
  Tags: #CreateAccount.
  Query #1: Query for users being created using "net user" command.
  "net user" commands are noisy, so needs to be joined with another signal -.
  E.g. in this example we look for use of uncommon & undocumented commandline switches (e.g. /ad instead of /add).
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
query: "```kusto\nDeviceProcessEvents\n// Pro-tip: \n// There are many different ways to run a process from a file - e.g. by using full path, env. variables, ~1 annotation, more...\n// So, to find executions of a known filename, better filter on the filename (and possibly on folder path) than on the commandline.\n| where FileName in~ (\"net.exe\", \"net1.exe\") and Timestamp > ago(3d)\n// Parse the user name from the commandline.\n// To have case-insensitive parsing use the i flag, to have non-greedy match (e.g. CreatedUser as short as possible), specify U flag:\n// \"kind=regex flags=i\"\n| parse kind=regex flags=iU ProcessCommandLine with * \"user \" CreatedUser \" \" * \"/ad\"\n// Filter rows where user could not be parsed - e.g. because it was not a user command, or the /add commandline switch was not specified.\n| where isnotempty(CreatedUser)\n// Every net.exe executed will run net1.exe with the same commandline.\n// in this where clause we remove such rows, as they duplicate the number of results we have without adding any value.\n| where not (FileName =~ \"net1.exe\" and InitiatingProcessFileName =~ \"net.exe\" and replace(\"net\", \"net1\", InitiatingProcessCommandLine) =~ ProcessCommandLine)\n// If /domain is specified, so the user is created on the domain controller.\n// Also, any prefix that's longer than 1 char will also do the same, e.g. /do, /dom, /doma, ....\n| extend CreatedOnLocalMachine=(ProcessCommandLine !contains \"/do\")\n| where ProcessCommandLine !contains \"/add\" or (CreatedOnLocalMachine == 0 and ProcessCommandLine !contains \"/domain\")\n| summarize MachineCount=dcount(DeviceName) by CreatedUser, CreatedOnLocalMachine, InitiatingProcessFileName, FileName, ProcessCommandLine, InitiatingProcessCommandLine \n```"
---

