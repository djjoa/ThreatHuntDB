---
id: 28f56c18-a66e-4c51-94f6-3c8902cb58af
name: PSExec Attrib commands
description: |
  Prior to deploying Macaw ransomware in an organization, adversaries wil use Attrib to display file attribute information on multiple drives and all subfolders.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
tactics:
  - Discovery
  - Ransomware
query: "```kusto\nDeviceProcessEvents \n| where InitiatingProcessParentFileName endswith \"PSEXESVC.exe\" \n| where InitiatingProcessCommandLine has \".bat\" \n| where FileName =~ \"cmd.exe\" and ProcessCommandLine has_all(\"-s\", \"-h\", \"-r\", \"-a\", \"*.*\") \n| take 100 \n```"
---

