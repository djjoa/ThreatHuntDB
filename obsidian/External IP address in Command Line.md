---
id: 2f6032ac-bb18-48b0-855a-7b05cf074957
name: External IP address in Command Line
description: |
  'This query looks for command lines that contain a public IP address. Attackers may use a hard coded IP for C2 or exfiltration.
    This query can be filtered to exclude network prefixes that are known to be legitimate.'
requiredDataConnectors:
  - connectorId: SecurityEvents
    dataTypes:
      - SecurityEvents
tactics:
  - CommandAndControl
  - Exfiltration
relevantTechniques:
  - T1041
  - T1071
query: |-
  ```kusto
  // Add any expected range prefixes here
    let exclusion_ranges = dynamic([""]);
    let ipv4_regex = "([^ ](\\b25[0-5]|\\b2[0-4][0-9]|\\b[01]?[0-9][0-9]?)(\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}|(\\b25[0-5]|\\b2[0-4][0-9]|\\b[01]?[0-9][0-9]?)(\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}[^ ])";
    let processes = dynamic(["cmd.exe", "powershell"]);
    SecurityEvent
    | where EventID == 4688
    | where Process has_any(processes)
    | extend IP = extract(ipv4_regex, 1, CommandLine)
    | where isnotempty(IP)
    | where not(ipv4_is_private(IP))
    | where not(has_any_ipv4_prefix(IP, exclusion_ranges))
    | summarize FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated), Hosts=makeset(Computer), Accounts=makeset(Account) by IP, CommandLine, Process
    | extend Host_count = array_length(Hosts)
    | sort by Host_count desc
    | project-reorder Host_count, IP, Process, CommandLine
  ```
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IP
version: 1.0.0
metadata:
  source:
    kind: Community
  author:
    name: Pete Bryan
  support:
    tier: Community
  categories:
    domains: ["Security - Network"]
---

