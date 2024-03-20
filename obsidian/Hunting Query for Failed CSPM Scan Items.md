---
id: 322591e4-5b68-4574-be00-2e1b618eab7c
name: Hunting Query for Failed CSPM Scan Items
description: |
  'Query Searches for all the failed scan results from the CSPM scans'
severity: High
requiredDataConnectors:
  - connectorId: PrancerLogData
    dataTypes:
      - prancer_CL
tactics:
  - Collection
relevantTechniques:
  - T0811
query: "```kusto\nprancer_CL\n| where act_s == 'alert'\n    and data_data_result_s == 'failed'\n| extend snapshot = parse_json(data_data_snapshots_s)\n| mv-expand snapshot \n| extend\n    id = tostring(snapshot.id),\n    structure = tostring(snapshot.structure),\n    reference = tostring(snapshot.reference),\n    source = tostring(snapshot.source),\n    collection = tostring(snapshot.collection),\n    type = tostring(snapshot.type),\n    region = tostring(snapshot.region),\n    resourceTypes = tostring(snapshot.resourceTypes),\n    path = tostring(snapshot.path)\n| summarize arg_min(id, *) by path, data_data_title_s\n| project Alert = data_data_title_s, Severity = data_data_severity_s, Cloud_Type = structure, Resource = path, Description = data_data_description_s, Remediation = data_data_remediation_description_s\n```"
entityMappings:
  - entityType: Azure Resource
    fieldMappings:
      - identifier: ResourceId
        columnName: Resource
---

