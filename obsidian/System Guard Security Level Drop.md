---
id: 701bee2f-c4d9-4f72-be03-e6bb1314e71c
name: System Guard Security Level Drop
description: |
  Goal: Find machines in the last N days where the SystemGuardSecurityLevel value NOW is less than it was BEFORE.
  Step 1: Get a list of all security levels in the system where the level is not null.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceEvents
query: "```kusto\nlet SecurityLevels = DeviceEvents\n| where Timestamp >= ago(7d)\n| where ActionType == \"DeviceBootAttestationInfo\"\n| extend AdditionalFieldData = parse_json(AdditionalFields)\n| project DeviceId, Timestamp, SystemGuardSecurityLevel = toint(AdditionalFieldData.SystemGuardSecurityLevel), ReportId\n| where isnotnull(SystemGuardSecurityLevel);\n// Step 2: Get the *latest* record for *each* machine from the SecurityLevels table\nlet LatestLevelsPerMachine = SecurityLevels\n // This is going to be the most recent event\n| summarize arg_max(Timestamp, SystemGuardSecurityLevel) by DeviceId\n| project DeviceId, LatestSystemGuardSecurityLevel=SystemGuardSecurityLevel, LatestEventTime=Timestamp;\n// Step 3: Join the two tables together where the LatestSystemGuardSecurityLevel is LESS than the SystemGuardSecurityLevel \nlet MachinesExhibitingSecurityLevelDrop = LatestLevelsPerMachine\n| join (\n SecurityLevels\n) on DeviceId\n| project-away DeviceId1\n| where LatestSystemGuardSecurityLevel < SystemGuardSecurityLevel \n| summarize arg_max(Timestamp, LatestSystemGuardSecurityLevel, SystemGuardSecurityLevel, LatestEventTime, ReportId) by DeviceId;\nMachinesExhibitingSecurityLevelDrop\n```"
---

