---
id: b1235ce0-06a0-446b-baad-852874f57bd4
name: GWorkspace - License Revoke and Assignment to User
description: |
  This hunting query searches for license revoke and assignment in quick succession to user, potential sign of data exfiltration.
  https://www.mitiga.io/blog/mitiga-security-advisory-lack-of-forensic-visibility-with-the-basic-license-in-google-drive
severity: Medium
requiredDataConnectors:
  - connectorId: GoogleWorkspaceReportsAPI
    dataTypes:
      - GWorkspaceActivityReports
tactics:
  - Exfiltration
relevantTechniques:
  - T1537
query: "```kusto\n// Adjust timeDelta (in minutes) to adjust the duration between two license revoke and assignment events   \nlet timeDelta = 15;\n// Adjust lookbackPeriod (in hours) to adjust the time window of search \nlet lookbackPeriod = 24h;\nlet usersWithLicenseRevoke = GWorkspaceActivityReports\n  | where TimeGenerated > ago(lookbackPeriod)\n  | where EventMessage =~ 'USER_LICENSE_REVOKE'\n  | sort by TimeGenerated desc \n  | summarize by TimeGenerated, UserEmail, EventMessage, SrcIpAddr;\nlet usersWithLicenseAssignment = GWorkspaceActivityReports\n  | where TimeGenerated > ago(lookbackPeriod)\n  | where EventMessage =~ 'USER_LICENSE_ASSIGNMENT'\n  | sort by TimeGenerated desc \n  | summarize by TimeGenerated, UserEmail, EventMessage, SrcIpAddr;\nusersWithLicenseRevoke\n  | join kind=inner usersWithLicenseAssignment on UserEmail\n  | extend isWithinDelta = iff(datetime_diff('minute', TimeGenerated1, TimeGenerated) < timeDelta, 1, 0)\n  | where isWithinDelta == 1\n  | summarize by UserEmail, SrcIpAddr\n  | extend Name = tostring(split(UserEmail,'@',0)[0]), UPNSuffix = tostring(split(UserEmail,'@',1)[0])\n  | extend Account_0_Name = Name\n  | extend Account_0_UPNSuffix = UPNSuffix\n  | extend IP_0_Address = SrcIpAddr\n```"
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

