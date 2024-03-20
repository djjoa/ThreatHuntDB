---
id: 29a1815a-3ada-4182-a178-e52c483d2f95
name: Solorigate Encoded Domain in URL
description: |
  'Looks for a logon domain seen in Azure AD logs appearing in a DNS query encoded with the DGA encoding used in the Solorigate incident.
  Reference: https://blogs.microsoft.com/on-the-issues/2020/12/13/customers-protect-nation-state-cyberattacks/'
requiredDataConnectors:
  - connectorId: DNS
    dataTypes:
      - DnsEvents
  - connectorId: AzureActiveDirectory
    dataTypes:
      - SigninLogs
tactics:
  - CommandAndControl
relevantTechniques:
  - T1568
tags:
  - Solorigate
  - NOBELIUM
query: "```kusto\nlet dictionary = dynamic([\"r\",\"q\",\"3\",\"g\",\"s\",\"a\",\"l\",\"t\",\"6\",\"u\",\"1\",\"i\",\"y\",\"f\",\"z\",\"o\",\"p\",\"5\",\"7\",\"2\",\"d\",\"4\",\"9\",\"b\",\"n\",\"x\",\"8\",\"c\",\"v\",\"m\",\"k\",\"e\",\"w\",\"h\",\"j\"]);\nlet regex_bad_domains = SigninLogs\n//Collect domains from tenant from signin logs\n| extend domain = tostring(split(UserPrincipalName, \"@\", 1)[0])\n| where domain != \"\"\n| summarize by domain\n| extend split_domain = split(domain, \".\")\n//This cuts back on domains such as na.contoso.com by electing not to match on the \"na\" portion\n| extend target_string = iff(strlen(split_domain[0]) <= 2, split_domain[1], split_domain[0])\n| extend target_string = split(target_string, \"-\")\n| mv-expand target_string\n//Rip all of the alphanumeric out of the domain name\n| extend string_chars = extract_all(@\"([a-z0-9])\", tostring(target_string))\n//Guid for tracking our data\n| extend guid = new_guid()\n//Expand to get all of the individual chars from the domain\n| mv-expand string_chars\n| extend chars = tostring(string_chars)\n//Conduct computation to encode the domain as per actor spec\n| extend computed_char = array_index_of(dictionary, chars)\n| extend computed_char = dictionary[(computed_char + 4) % array_length(dictionary)]\n| summarize make_list(computed_char,250) by guid, domain\n| extend target_encoded = tostring(strcat_array(list_computed_char, \"\"))\n//These are probably too small, but can be edited (expect FP's when going too small)\n| where strlen(target_encoded) > 5\n| distinct target_encoded\n| summarize make_set(target_encoded,250)\n//Key to join to DNS\n| extend key = 1;\nDnsEvents\n| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) by Name\n| extend key = 1\n//For each DNS query join the malicious domain list\n| join kind=inner ( \n    regex_bad_domains\n) on key\n| project-away key\n//Expand each malicious key for each DNS query observed\n| mv-expand set_target_encoded\n//IndexOf allows us to fuzzy match on the substring\n| extend match = indexof(Name, set_target_encoded)\n| where match > -1\n| extend DNS_0_DomainName = Name\n```"
entityMappings:
  - entityType: DNS
    fieldMappings:
      - identifier: DomainName
        columnName: Name
---

