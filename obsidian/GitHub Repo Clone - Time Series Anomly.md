---
id: ccef3c74-4b4f-445b-8109-06d38687e4a4
name: GitHub Repo Clone - Time Series Anomly
description: |
  'Attacker can exfiltrate data from your GitHub repository by cloning it. This hunting query tracks clone activities for each repository, allowing quick identification of anomalies/excessive clones to investigate repo access & permissions.'
description_detailed: |
  'Attacker can exfiltrate data from you GitHub repository after gaining access to it by performing clone action. This hunting queries allows you to track the clones activities for each of your repositories. The visualization allow you to quickly identify anomalies/excessive clone, to further investigate repo access & permissions'
requiredDataConnectors: []
tactics:
  - Collection
relevantTechniques:
  - T1213
query: "```kusto\n\nlet min_t = toscalar(GitHubRepo\n| summarize min(timestamp_t));\nlet max_t = toscalar(GitHubRepo\n| summarize max(timestamp_t));\nGitHubRepo\n| where Action == \"Clones\"\n| distinct TimeGenerated, Repository, Count\n| make-series num=sum(tolong(Count)) default=0 on TimeGenerated in range(min_t, max_t, 1h) by Repository \n| extend (anomalies, score, baseline) = series_decompose_anomalies(num, 1.5, -1, 'linefit')\n| render timechart \n```"
version: 1.0.1
metadata:
  source:
    kind: Community
  author:
    name: itay6588
  support:
    tier: Microsoft
  categories:
    domains: ["Security - Threat Protection"]
---

