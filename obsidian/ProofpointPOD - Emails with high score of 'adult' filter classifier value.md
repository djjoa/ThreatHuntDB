---
id: 0794a162-8635-43fd-81ed-2cf2604575b1
name: ProofpointPOD - Emails with high score of 'adult' filter classifier value
description: |
  'Search for emails with high score of 'adult' filter classifier value.'
requiredDataConnectors:
  - connectorId: ProofpointPOD
    dataTypes:
      - ProofpointPOD_message_CL
tactics:
  - InitialAccess
query: |-
  ```kusto
  let scoreThreshold = 80;
  ProofpointPOD
  | where EventType == 'message'
  | where NetworkDirection == 'inbound'
  | where todynamic(FilterModulesSpamScoresClassifiers).adult > scoreThreshold
  ```
---

