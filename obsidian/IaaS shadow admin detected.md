---
id: fad675f5-b743-40c6-873d-019de93f18db
name: IaaS shadow admin detected
description: |
  'detects shadow admin users in AWS or Azure.'
requiredDataConnectors:
  - connectorId: Authomize
    dataTypes:
      - Authomize_v2_CL
tactics:
  - PrivilegeEscalation
relevantTechniques:
  - T1089
query: |-
  ```kusto
  Authomize_v2_CL
  | extend EventID = id_s, Policy = policy_name_s, Severity = severity_s,Description = description_s,Recommendation = recommendation_s,URL = url_s,Tactics = tactics_s
  | where Policy has "IaaS shadow admin detected"
  | project EventID, Policy, Severity, Description, Recommendation, URL, Category, Tactics
  | extend CloudApplication_0_Name = Policy
  ```
entityMappings:
  - entityType: CloudApplication
    fieldMappings:
      - identifier: Name
        columnName: Policy
version: 1.0.0
---

