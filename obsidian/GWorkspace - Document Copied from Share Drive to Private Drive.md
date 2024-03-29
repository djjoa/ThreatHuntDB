---
id: 69e8a40f-6508-4f43-8eef-2f78ad6174df
name: GWorkspace - Document Copied from Share Drive to Private Drive
description: |
  This hunting query searches for document copy activity from shared drive to a private drive, potential sign of data exfiltration.
  https://www.mitiga.io/blog/mitiga-security-advisory-lack-of-forensic-visibility-with-the-basic-license-in-google-drive
severity: Medium
requiredDataConnectors:
  - connectorId: GoogleWorkspaceReportsAPI
    dataTypes:
      - GWorkspaceActivityReports
tactics:
  - Exfiltration
  - Impact
relevantTechniques:
  - T1537
  - T1565
query: |-
  ```kusto
  GWorkspaceActivityReports
  | where TimeGenerated > ago(24h)
  | where EventMessage =~ 'source_copy'
  | project TimeGenerated, ActorEmail, SrcIpAddr, DocTitle
  | extend Name = tostring(split(ActorEmail,'@',0)[0]), UPNSuffix = tostring(split(ActorEmail,'@',1)[0])
  | extend Account_0_Name = Name
  | extend Account_0_UPNSuffix = UPNSuffix
  | extend IP_0_Address = SrcIpAddr
  ```
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: Name
      - identifier: UPNSuffix
        columnName: UPNSuffix
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: SrcIpAddr
version: 1.0.0
---

