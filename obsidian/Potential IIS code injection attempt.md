---
id: 96977c95-74b4-4cc2-b1a7-6a3ab17bd3f9
name: Potential IIS code injection attempt
description: |
  'Potential code injection into web server roles via IIS logs scan. Represents attempt to gain initial access using drive-by compromise technique. Detection flags events for review and filtering of authorized activity.'
description_detailed: "'Potential code injection into web server roles via scan of IIS logs. This represents an attempt to gain initial access to a system using a \ndrive-by compromise technique.  This sort of attack happens routinely as part of security scans, of both authorized and malicious types. \nThe initial goal of this detection is to flag these events when they occur and give an opportunity to review the data and filter out authorized activity.'\n"
requiredDataConnectors:
  - connectorId: AzureMonitor(IIS)
    dataTypes:
      - W3CIISLog
tactics:
  - InitialAccess
relevantTechniques:
  - T1189
  - T1190
query: "```kusto\n\n// set cIP and csMethod count limit to indicate potentially noisy events, this will be listed at the top of the results \n// for any returns that are gt or equal to the default of 50\nlet cIP_MethodCountLimit = 50;\n// Exclude common csMethods, add/modify this list as needed for your environment\nlet csMethodExclude = dynamic(['GET', 'DEBUG', 'DELETE', 'LOCK', 'MKCOL', 'MOVE', 'PATCH', 'POST', 'PROPPATCH', \n'PUT', 'SEARCH', 'TRACE', 'TRACK', 'UNLOCK', 'OPTIONS', 'HEAD', 'RPC_IN_DATA', 'RPC_OUT_DATA', 'PROPFIND','BITS_POST','CCM_POST']);\n// Include in the list expected IPs where remote methods such as vuln scanning may be expected for your environment\nlet expectedIPs = dynamic(['X.X.X.X', 'Y.Y.Y.Y']);\nlet codeInjectionAttempts = W3CIISLog\n// Exclude private ip ranges from cIP list\n| where ipv4_is_private(cIP) == false\n| where cIP != \"::1\"\n| where cIP !in (expectedIPs)\n| project TimeGenerated, cIP, csUserName, csMethod, csCookie, csHost, sIP, scStatus, csUriStem, csUriQuery, csUserAgent, csReferer \n// Throwing entire record into a single string column for attributable string matching\n| extend pak = tostring(pack_all())\n// Adding \"arr\" column containing indicators of matched suspicious strings\n| extend arr = dynamic([])\n| extend arr = iff(pak contains '<script' , array_concat(arr, pack_array('STRING MATCH : script')), arr)\n| extend arr = iff(pak contains '%3Cscript' , array_concat(arr, pack_array('STRING MATCH : script')), arr)\n| extend arr = iff(pak contains '%73%63%72%69%70%74' , array_concat(arr, pack_array('STRING MATCH : encoded script')), arr)\n| extend arr = iff(pak contains '<img' , array_concat(arr, pack_array('STRING MATCH : img')), arr)\n| extend arr = iff(pak contains '%3Cimg' , array_concat(arr, pack_array('STRING MATCH : img')), arr)\n| extend arr = iff(pak contains 'passwd' , array_concat(arr, pack_array('STRING MATCH : passwd')), arr)\n| extend arr = iff(csUserAgent contains 'nmap' , array_concat(arr, pack_array('STRING MATCH : nmap')), arr)\n| extend arr = iff(csUserAgent contains 'nessus' , array_concat(arr, pack_array('STRING MATCH : nessus')), arr)\n| extend arr = iff(csUserAgent contains 'qualys' , array_concat(arr, pack_array('STRING MATCH : qualys')), arr)\n| extend arr = iff(csMethod !in (csMethodExclude), array_concat(arr, pack_array('INVALID HTTP METHOD')), arr)\n| extend arr = iff(csUriStem == '/current_config/passwd' , array_concat(arr, pack_array('STRING MATCH : dahua scan url' )), arr)\n| extend arr = iff(csUriQuery contains '..' and csUriQuery !endswith '...', array_concat(arr, pack_array('BACKTRACK ATTEMPT IN QUERY')), arr)\n| extend arr = iff(csUriQuery contains 'http://www.webscantest.com' , array_concat(arr, pack_array('STRING MATCH : webscantest')), arr)\n| extend arr = iff(csUriQuery contains 'http://appspidered.rapid7.com' , array_concat(arr, pack_array('STRING MATCH : appspider')), arr)\n| where array_length(arr) > 0\n| project-away pak;\nlet cIP_MethodHighCount = codeInjectionAttempts \n| summarize StartTime = max(TimeGenerated), EndTime = min(TimeGenerated), cIP_MethodCount = count() \nby cIP, tostring(arr), cIP_MethodCountType = \"High Count of cIP and csMethod, this may be noise\" \n| where cIP_MethodCount >=  cIP_MethodCountLimit;\nlet codeInjectAtt = \ncodeInjectionAttempts \n| summarize StartTime = max(TimeGenerated), EndTime = min(TimeGenerated), cIP_MethodCount = count() \nby cIP, cIP_MethodCountType = \"Count of repeated entries, this is to reduce rowsets returned\", csMethod, \ntostring(arr), csHost, scStatus, sIP, csUriStem, csUriQuery, csUserName, csUserAgent, csCookie, csReferer;\n// union the events and sort by cIP_MethodCount to identify potentially noisy entries.  Additionally, cIP_MethodCountType \n// indicates whether it is a high count or simply a count of repeated entries\n(union isfuzzy=true\ncIP_MethodHighCount, codeInjectAtt\n| sort by cIP_MethodCount desc, cIP desc, StartTime desc)\n| extend timestamp = StartTime, IPCustomEntity = cIP, HostCustomEntity = csHost, AccountCustomEntity = csUserName, URLCustomEntity = csUriQuery\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountCustomEntity
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPCustomEntity
  - entityType: URL
    fieldMappings:
      - identifier: Url
        columnName: UrlCustomEntity
  - entityType: Host
    fieldMappings:
      - identifier: FullName
        columnName: HostCustomEntity
version: 1.0.1
metadata:
  source:
    kind: Community
  author:
    name: Shain
  support:
    tier: Microsoft
  categories:
    domains: ["Security - Threat Protection"]
---

