---
id: 09e45ec6-ac42-4b5a-be69-54623c4aa062
name: Possible Linux attack toolkit detected via Syslog data
description: |
  'This query searches for usage of attack toolkits associated with massive scanning or exploitation of remote code execution vulnerability in Log4j component of Apache.'
description-detailed: |
  'This query uses syslog data to alert on any attack toolkits associated with massive scanning or exploitation attempts against a known vulnerability.Attackers may perform such operations as seen recently to exploit the remote code execution vulnerability in Log4j component of Apache to scope and prioritize post-compromise objectives.
  For more details on Apache Log4j Remote Code Execution Vulnerability - https://community.riskiq.com/article/505098fc/description
  Find more details on collecting EXECVE data into Microsoft Sentinel - https://techcommunity.microsoft.com/t5/azure-sentinel/hunting-threats-on-linux-with-azure-sentinel/ba-p/1344431'
requiredDataConnectors:
  - connectorId: Syslog
    dataTypes:
      - Syslog
tactics:
  - Reconnaissance
  - Execution
relevantTechniques:
  - T1595
  - T1203
tags:
  - CVE-2021-44228
  - Log4j
  - Log4Shell
query: "```kusto\nSyslog\n| where Facility == 'user'\n| where SyslogMessage has \"AUOMS_EXECVE\"\n| parse SyslogMessage with \"type=\" EventType \" audit(\" * \"): \" EventData\n| where EventType =~ \"AUOMS_EXECVE\"\n| parse EventData with * \"syscall=\" syscall \" syscall_r=\" * \" success=\" success \" exit=\" exit \" a0\" * \" ppid=\" ppid \" pid=\" pid \" audit_user=\" audit_user \" auid=\" auid \" user=\" user \" uid=\" uid \" group=\" group \" gid=\" gid \"effective_user=\" effective_user \" euid=\" euid \" set_user=\" set_user \" suid=\" suid \" filesystem_user=\" filesystem_user \" fsuid=\" fsuid \" effective_group=\" effective_group \" egid=\" egid \" set_group=\" set_group \" sgid=\" sgid \" filesystem_group=\" filesystem_group \" fsgid=\" fsgid \" tty=\" tty \" ses=\" ses \" comm=\\\"\" comm \"\\\" exe=\\\"\" exe \"\\\"\" * \"cwd=\\\"\" cwd \"\\\"\" * \"name=\\\"\" name \"\\\"\" * \"cmdline=\" cmdline  \n| extend cmdline = trim_end('redactors=.*',cmdline) \n| where (exe has \"java\" and cmdline has \"JNDI-Injection-Exploit\") or (exe has \"javac\" and cmdline has \"log4j-payload-generator\") or (cmdline has \"LogMePwn\" and cmdline has \"git clone\")\n| project TimeGenerated, Computer, audit_user, user, cmdline\n| extend timestamp = TimeGenerated\n| extend Host_0_HostName = Computer\n| extend Account_0_Name = user\n| sort by TimeGenerated desc\n```"
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: Computer
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: user
version: 1.0.2
---
