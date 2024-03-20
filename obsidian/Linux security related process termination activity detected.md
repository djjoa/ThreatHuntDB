---
id: 020b05d3-6447-402c-87b6-f8faff7c7e19
name: Linux security related process termination activity detected
description: |
  'This query alerts on attempts to terminate security monitoring processes on the host. Attackers often try to terminate such processes post-compromise to exploit the Log4j vulnerability.'
description-detailed: "'This query will alert on any attempts to terminate processes related to security monitoring on the host. \nAttackers will often try to terminate such processes post-compromise as seen recently to exploit the remote code execution vulnerability in Log4j component of Apache.\nFor more details on Apache Log4j Remote Code Execution Vulnerability - https://community.riskiq.com/article/505098fc/description\nFind more details on collecting EXECVE data into Microsoft Sentinel - https://techcommunity.microsoft.com/t5/azure-sentinel/hunting-threats-on-linux-with-azure-sentinel/ba-p/1344431'\n"
requiredDataConnectors:
  - connectorId: Syslog
    dataTypes:
      - Syslog
tactics:
  - DefenseEvasion
relevantTechniques:
  - T1489
tags:
  - CVE-2021-44228
  - Log4j
  - Log4Shell
query: |-
  ```kusto
  Syslog
  | where Facility == 'user'
  | where SyslogMessage has "AUOMS_EXECVE"
  | parse SyslogMessage with "type=" EventType " audit(" * "): " EventData
  | where EventType =~ "AUOMS_EXECVE"
  | parse EventData with * "syscall=" syscall " syscall_r=" * " success=" success " exit=" exit " a0" * " ppid=" ppid " pid=" pid " audit_user=" audit_user " auid=" auid " user=" user " uid=" uid " group=" group " gid=" gid "effective_user=" effective_user " euid=" euid " set_user=" set_user " suid=" suid " filesystem_user=" filesystem_user " fsuid=" fsuid " effective_group=" effective_group " egid=" egid " set_group=" set_group " sgid=" sgid " filesystem_group=" filesystem_group " fsgid=" fsgid " tty=" tty " ses=" ses " comm=\"" comm "\" exe=\"" exe "\"" * "cwd=\"" cwd "\"" * "name=\"" name "\"" * "cmdline=" cmdline
  | extend cmdline = trim_end('redactors=.*',cmdline)
  | where cmdline has_any ("service apparmor stop","service aliyun.service stop","systemctl disable apparmor","systemctl disable aliyun.service")
  or  (exe has "pkill" and cmdline has_any ("omsagent","auoms","omiagent","waagent") and cmdline !has "/omsagent/plugin/pi"and cmdline !has "/omsconfig/modules")
  | project TimeGenerated, Computer, audit_user, user, cmdline
  | extend timestamp = TimeGenerated
  | extend Host_0_HostName = Computer
  | extend Account_0_Name = user
  | sort by TimeGenerated desc
  ```
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
