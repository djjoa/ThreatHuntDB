---
id: 78882f9a-f3ef-4010-973c-3f6336f5bef7
name: Suspicious Base64 download activity detected
description: |
  'Query detects Base64 obfuscated scripts for malicious file execution. This technique is used by attackers to exploit a remote code execution vulnerability in the Apache Log4j to evade detection.'
description-detailed: |
  'This hunting query will help detect suspicious encoded Base64 obfuscated scripts that attackers use to encode payloads for downloading and executing malicious files.
  This technique is often used by attackers and was recently used  to exploit a remote code execution vulnerability in the Log4j component of Apache in order to evade detection and stay persistent in the network.
  For more details on Apache Log4j Remote Code Execution Vulnerability - https://community.riskiq.com/article/505098fc/description
  Find more details on collecting EXECVE data into Microsoft Sentinel - https://techcommunity.microsoft.com/t5/azure-sentinel/hunting-threats-on-linux-with-azure-sentinel/ba-p/1344431'
requiredDataConnectors:
  - connectorId: Syslog
    dataTypes:
      - Syslog
tactics:
  - Persistence
  - Execution
relevantTechniques:
  - T1059
  - T1053
tags:
  - CVE-2021-44228
query: "```kusto\nSyslog\n| where Facility == 'user'\n| where SyslogMessage has \"AUOMS_EXECVE\"\n| parse SyslogMessage with \"type=\" EventType \" audit(\" * \"): \" EventData\n| project TimeGenerated, EventType, Computer, EventData\n| where EventType =~ \"AUOMS_EXECVE\"\n| parse EventData with * \"syscall=\" syscall \" syscall_r=\" * \" success=\" success \" exit=\" exit \" a0\" * \" ppid=\" ppid \" pid=\" pid \" audit_user=\" audit_user \" auid=\" auid \" user=\" user \" uid=\" uid \" group=\" group \" gid=\" gid \"effective_user=\" effective_user \" euid=\" euid \" set_user=\" set_user \" suid=\" suid \" filesystem_user=\" filesystem_user \" fsuid=\" fsuid \" effective_group=\" effective_group \" egid=\" egid \" set_group=\" set_group \" sgid=\" sgid \" filesystem_group=\" filesystem_group \" fsgid=\" fsgid \" tty=\" tty \" ses=\" ses \" comm=\\\"\" comm \"\\\" exe=\\\"\" exe \"\\\"\" * \"cwd=\\\"\" cwd \"\\\"\" * \"name=\\\"\" name \"\\\"\" * \"cmdline=\" cmdline\n| extend cmdline = trim_end('redactors=.*',cmdline) \n| where cmdline has \"/Basic/Command/Base64/\"\n| where exe has_any (\"curl\", \"wget\")\n| parse cmdline with * \"Base64/\" OriginalEncodedCommand:string\n| extend EncodedCommand = extract(\"((?:[A-Za-z0-9+/-]{4})*(?:[A-Za-z0-9+/-]{2}==|[A-Za-z0-9+/-]{3}=|[A-Za-z0-9+/-]{4}))\", 1, OriginalEncodedCommand) \n| extend DecodedCommand = base64_decode_tostring(EncodedCommand) \n| project TimeGenerated, Computer, audit_user, user, cmdline, DecodedCommand, EncodedCommand\n| extend timestamp = TimeGenerated\n| extend Host_0_HostName = Computer\n| extend Account_0_Name = user\n| sort by TimeGenerated desc\n```"
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: Computer
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: user
version: 1.0.3
---

