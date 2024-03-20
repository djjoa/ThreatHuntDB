---
id: 3e43fe23-c6c0-45ca-b680-263e8afada95
name: Suspicious Shell script detected
description: |
  'This query detects post-compromise suspicious shell scripts that attackers use for downloading and executing malicious files. This technique is often used by attackers and was recently used to exploit the Log4j vulnerability.'
description-detailed: |
  'This hunting query will help detect post compromise suspicious shell scripts that attackers use for downloading and executing malicious files.
  This technique is often used by attackers and was recently used  to exploit a remote code execution vulnerability in the Log4j component of Apache in order to evade detection and stay persistent or for more exploitation in the network.
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
query: "```kusto\nSyslog\n| where Facility == 'user'\n| where SyslogMessage has \"AUOMS_EXECVE\"\n| parse SyslogMessage with \"type=\" EventType \" audit(\" * \"): \" EventData\n| where EventType =~ \"AUOMS_EXECVE\"\n| project TimeGenerated, EventType, Computer, EventData\n| parse EventData with * \"syscall=\" syscall \" syscall_r=\" * \" success=\" success \" exit=\" exit \" a0\" * \" ppid=\" ppid \" pid=\" pid \" audit_user=\" audit_user \" auid=\" auid \" user=\" user \" uid=\" uid \" group=\" group \" gid=\" gid \"effective_user=\" effective_user \" euid=\" euid \" set_user=\" set_user \" suid=\" suid \" filesystem_user=\" filesystem_user \" fsuid=\" fsuid \" effective_group=\" effective_group \" egid=\" egid \" set_group=\" set_group \" sgid=\" sgid \" filesystem_group=\" filesystem_group \" fsgid=\" fsgid \" tty=\" tty \" ses=\" ses \" comm=\\\"\" comm \"\\\" exe=\\\"\" exe \"\\\"\" * \"cwd=\\\"\" cwd \"\\\"\" * \"name=\\\"\" name \"\\\"\" * \"cmdline=\" cmdline\n| extend cmdline = trim_end('redactors=.*',cmdline) \n| where exe has_any (\"bash\",\"dash\")\n| where cmdline matches regex  \"[0-9]{1,3}\\\\.[0-9]{1,3}\\\\.[0-9]{1,3}\\\\.[0-9]{1,3}\"\n| where cmdline has \"curl\" and cmdline has \"wget\"\n| project TimeGenerated, Computer, audit_user, user, cmdline\n| extend timestamp = TimeGenerated\n| extend Host_0_HostName = Computer\n| extend Account_0_Name = user\n| sort by TimeGenerated desc\n```"
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

