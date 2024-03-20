---
id: eba83f84-b844-4fc9-96f4-cb51b0b20c1d
name: Create account (1)
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
      - DeviceEvents
query: "```kusto\n\n// Query #2: Query for accounts created on machines onboarded with Sense.\n// Create account event is noisy, so we need to join it with some other signal.\n// E.g. In this query we look for accounts created which name resembles \"administrator\".\n//      Using account names similar to known common account names is a common way to be evade the human analyst eye.\nDeviceEvents\n| where ActionType == \"UserAccountCreated\"\n// To look for account names similar to administrator, we'll simply query for the prefix and suffix,\n// because these letters matter most to the human perception: https://en.wikipedia.org/wiki/Typoglycemia\n// Calculating distance functions is possible but will be much more complicated - \n// and looking for prefix and suffix should work in this case pretty well.\n| where AccountName startswith \"ad\" and AccountName endswith \"or\" and AccountName !~ \"administrator\"\n// Note: For the UserAccountCreated event we do not know the details of the process / account that was used to create this new account.\n| project AccountName, AccountDomain, DeviceName, Timestamp\n| limit 100```"
---

