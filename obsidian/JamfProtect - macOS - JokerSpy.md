---
id: 8d9a199b-7968-476b-b02b-d030a010609c
name: JamfProtect - macOS - JokerSpy
description: |
  'Use this query to look for alerts related to JokerSpy activity, Known to use various back doors to deploy spyware on victims' systems in order to perform reconnaissance and for command and control.'
requiredDataConnectors:
  - connectorId: JamfProtect
    dataTypes:
      - jamfprotect_CL
tactics:
  - Execution
  - Masquerading
relevantTechniques:
  - T1059
  - T1036
query: "```kusto\nJamfProtect\n| where TargetProcessSHA1 has \"937a9811b3e5482eb8f96832454723d59229f945\" \n    or TargetProcessSHA1 has \"c7d6ede0f6ac9f060ae53bb1db40a4fbe96f9ceb\"\n    or TargetProcessSHA1 has \"bd8626420ecfd1ab5f4576d83be35edecd8fa70e\"\n    or TargetProcessSHA1 has \"370a0bb4177eeebb2a75651a8addb0477b7d610b\"\n    or TargetProcessSHA1 has \"1ed2c5ee95ab77f8e1c1f5e2bd246589526c6362\"\n    or TargetProcessSHA1 has \"1f99081affd7bef83d44e0072eb860d515893698\"\n    or TargetProcessSHA1 has \"76b790eb3bed4a625250b961a5dda86ca5cd3a11\"\n    or DnsQueryName contains \"git-hub.me\"\n    or DnsQueryName contains \"app.influmarket.org\"\n    or EventMatch contains \"jokerspy_a\"\n```"
---

