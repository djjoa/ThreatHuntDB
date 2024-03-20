---
id: c46eeb45-c324-4a84-9df1-248c6d1507bb
name: Risky base64 encoded command in URL
description: |
  'This hunting query will detect risky base64 encoded commands are seen in web requests. Some threat actors transmit base64 commands from the target host
  back to the C2 servers so they know which command has been executed. This query also reguarly illumniates base64 encoded webshells being injected.
  The limitation of this query is that base64 is case sensitive, so different case versions of each command need generating for full coverage. This query
  computes base64 permutations for each command, resulting in 3 possible permutations depending on padding.'
requiredDataConnectors:
  - connectorId: Zscaler
    dataTypes:
      - CommonSecurityLog
  - connectorId: Fortinet
    dataTypes:
      - CommonSecurityLog
  - connectorId: CheckPoint
    dataTypes:
      - CommonSecurityLog
  - connectorId: PaloAltoNetworks
    dataTypes:
      - CommonSecurityLog
tactics:
  - CommandAndControl
relevantTechniques:
  - T1071.001
tags:
  - POLONIUM
query: "```kusto\nlet mapping = datatable (CommandFound:string, match_list:dynamic) [\n\"whoami\", dynamic(['d2hvYW1p', 'dob2Fta', '3aG9hbW']),\n\"net share\", dynamic(['bmV0IHNoYXJl', '5ldCBzaGFyZ', 'uZXQgc2hhcm']),\n\"net use\", dynamic(['bmV0IHVzZ', '5ldCB1c2', 'uZXQgdXNl']),\n\"net view\", dynamic(['bmV0IHZpZX', '5ldCB2aWV3', 'uZXQgdmlld']),\n\"ipconfig\", dynamic(['aXBjb25maWc', 'lwY29uZmln', 'pcGNvbmZpZ']),\n\"net sh\", dynamic(['bmV0c2gg', '5ldHNoI', 'uZXRzaC']),\n\"schtasks\", dynamic(['2NodGFza3', 'NjaHRhc2tz', 'zY2h0YXNrc']),\n\"Invoke- \", dynamic(['SW52b2tlL', 'ludm9rZS', 'JbnZva2Ut']),\n];\nlet riskyCommandRegex = @\"(d2hvYW1p|dob2Fta|3aG9hbW|bmV0IHNoYXJl|5ldCBzaGFyZ|uZXQgc2hhcm|bmV0IHVzZ|5ldCB1c2|uZXQgdXNl|bmV0IHZpZX|5ldCB2aWV3|uZXQgdmlld|aXBjb25maWc|lwY29uZmln|pcGNvbmZpZ|bmV0c2gg|5ldHNoI|uZXRzaC|2NodGFza3|NjaHRhc2tz|zY2h0YXNrc|SW52b2tlL|ludm9rZS|JbnZva2Ut)\";\nCommonSecurityLog\n| where TimeGenerated > ago(3d)\n| where RequestURL matches regex riskyCommandRegex\n| extend B64MatchData = extract_all(riskyCommandRegex, RequestURL)\n| where isnotempty(B64MatchData)\n| mv-expand B64MatchData to typeof(string)\n| join kind=leftouter ( \n    mapping\n    | mv-expand match_list to typeof(string)\n) on $left.B64MatchData == $right.match_list\n| project TimeGenerated, B64MatchData, CommandFound, RequestURL, RequestMethod, DestinationHostName, DestinationIP, SourceIP, DeviceVendor, DeviceProduct, Activity\n| extend timestamp = TimeGenerated\n| extend HostName = tostring(split(DestinationHostName, '.', 0)[0]), DnsDomain = tostring(strcat_array(array_slice(split(DestinationHostName, '.'), 1, -1), '.'))\n| extend IP_0_Address = SourceIP\n| extend IP_1_Address = DestinationIP\n| extend DNS_0_HostName = HostName\n| extend DNS_0_DnsDomain = DnsDomain  \n```"
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: SourceIP
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: DestinationIP
  - entityType: DNS
    fieldMappings:
      - identifier: HostName
        columnName: HostName
      - identifier: DnsDomain
        columnName: DnsDomain
version: 1.0.1
---

