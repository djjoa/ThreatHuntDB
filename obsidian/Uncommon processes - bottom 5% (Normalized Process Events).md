---
id: 4e3af8e3-a29f-4eec-ac25-55517dca6512
name: Uncommon processes - bottom 5% (Normalized Process Events)
description: "'Shows the rarest processes seen running for the first time. (Performs best over longer time ranges - eg 3+ days rather than 24 hours!)\nThese new processes could be benign new programs installed on hosts; \nHowever, especially in normally stable environments, these new processes could provide an indication of an unauthorized/malicious binary that has been installed and run. \nReviewing the wider context of the logon sessions in which these binaries ran can provide a good starting point for identifying possible attacks.'\n"
requiredDataConnectors: []
tactics:
  - Execution
query: "```kusto\nlet freqs = imProcessCreate \n  // filter out common randomly named files related to MSI installers and browsers\n  | where not(Process has_all ('TRA', '.tmp') and Process matches regex @\"\\\\TRA[0-9A-Fa-f]{3,4}\\.tmp\")\n  | where not(Process has_all ('MSI', '.tmp') and Process matches regex @\"\\\\MSI[0-9A-Fa-f]{3,4}\\.tmp\")\n  | extend FileName = tostring(split(Process, '\\\\')[-1])\n  // normalize guids\n  | extend FileName = replace(\"[0-9A-Fa-f]{8}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{12}\", \"<guid>\", FileName)\n  | extend FileName = replace(@'\\d', 'n', FileName)\n  | summarize frequency=count(), Since=min(TimeGenerated), LastSeen=max(TimeGenerated) by FileName , EventVendor, EventProduct;\nlet precentile_5 = toscalar ( freqs | summarize percentiles(frequency, 5));\nfreqs\n  | where frequency <= precentile_5\n  | order by frequency asc\n  | project FileName, frequency, precentile_5, Since, LastSeen , EventVendor, EventProduct\n  // restrict results to unusual processes seen in last day \n  | where LastSeen >= ago(1d)\n  | extend timestamp = LastSeen\n```"
---

