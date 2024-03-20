---
id: e178baf5-3cf3-4960-8ca4-8da6d90d8206
name: Suspicious manipulation of firewall detected via Syslog data
description: |
  'This query searches for any suspicious manipulation of firewall often performed by attackers after exploiting remote code execution vulnerability in Log4j component of Apache for C2 communications or exfiltration.'
description-detailed: |
  'This query uses syslog data to alert on any suspicious manipulation of firewall to evade defenses.
  Attackers often perform such operation as seen recently to exploit the remote code execution vulnerability in Log4j component of Apache for C2 communications or exfiltration.
  For more details on Apache Log4j Remote Code Execution Vulnerability - https://community.riskiq.com/article/505098fc/description
  Find more details on collecting EXECVE data into Microsoft Sentinel - https://techcommunity.microsoft.com/t5/azure-sentinel/hunting-threats-on-linux-with-azure-sentinel/ba-p/1344431'
requiredDataConnectors:
  - connectorId: Syslog
    dataTypes:
      - Syslog
tactics:
  - DefenseEvasion
relevantTechniques:
  - T1562
tags:
  - CVE-2021-44228
  - Log4j
  - Log4Shell
query: "```kusto\nSyslog\n| where Facility == 'user'\n| where SyslogMessage has \"AUOMS_EXECVE\"\n| parse SyslogMessage with \"type=\" EventType \" audit(\" * \"): \" EventData\n| where EventType =~ \"AUOMS_EXECVE\"\n| parse EventData with * \"syscall=\" syscall \" syscall_r=\" * \" success=\" success \" exit=\" exit \" a0\" * \" ppid=\" ppid \" pid=\" pid \" audit_user=\" audit_user \" auid=\" auid \" user=\" user \" uid=\" uid \" group=\" group \" gid=\" gid \"effective_user=\" effective_user \" euid=\" euid \" set_user=\" set_user \" suid=\" suid \" filesystem_user=\" filesystem_user \" fsuid=\" fsuid \" effective_group=\" effective_group \" egid=\" egid \" set_group=\" set_group \" sgid=\" sgid \" filesystem_group=\" filesystem_group \" fsgid=\" fsgid \" tty=\" tty \" ses=\" ses \" comm=\\\"\" comm \"\\\" exe=\\\"\" exe \"\\\"\" * \"cwd=\\\"\" cwd \"\\\"\" * \"name=\\\"\" name \"\\\"\" * \"cmdline=\" cmdline\n| extend cmdline = trim_end('redactors=.*',cmdline) \n| where cmdline has_any (\"SuSEfirewall2 stop\",\"reSuSEfirewall2 stop\",\"ufw stop\",\"ufw disable\")\n| project TimeGenerated, Computer, audit_user, user, cmdline\n| extend timestamp = TimeGenerated\n| extend Account_0_Name = user\n| extend Host_0_HostName = Computer\n| sort by TimeGenerated desc\n```"
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
