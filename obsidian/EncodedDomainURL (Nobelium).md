---
id: c561bf69-6a6c-4d0a-960a-b69e0e7c8f51
name: EncodedDomainURL [Nobelium]
description: |
  Looks for a logon domain in the Microsoft Entra ID logs,  encoded with the same DGA encoding used in the Nobelium campaign.
  See Important steps for customers to protect themselves from recent nation-state cyberattacks for more on the Nobelium campaign (formerly known as Solorigate).
  This query is inspired by an Azure Sentinel detection.
  References:
  https://blogs.microsoft.com/on-the-issues/2020/12/13/customers-protect-nation-state-cyberattacks/
  https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/DnsEvents/Solorigate-Encoded-Domain-URL.yaml
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceNetworkEvents
      - DeviceEvents
      - IdentityQueryEvents
      - AADSignInEventsBeta
tactics:
  - Command and control
tags:
  - Nobelium
query: "```kusto\nlet timeFrame = ago(1d);\nlet relevantDeviceNetworkEvents = \n  DeviceNetworkEvents\n  | where Timestamp >= timeFrame\n  | where RemoteUrl !has \"\\\\\" and RemoteUrl !has \"/\"\n  | project-rename DomainName = RemoteUrl\n  | summarize by DomainName;\nlet relevantDeviceEvents =\n  DeviceEvents\n  | where Timestamp >= timeFrame\n  | where ActionType == \"DnsQueryResponse\"\n  | extend query = extractjson(\"$.DnsQueryString\", AdditionalFields)  \n  | where isnotempty(query)\n  | project-rename DomainName = query\n  | summarize by DomainName;\nlet relevantIdentityQueryEvents =\n  IdentityQueryEvents \n  | where Timestamp >= timeFrame\n  | where ActionType == \"DNS query\"\n  | where Protocol == \"Dns\"\n  | project-rename DomainName = QueryTarget\n  | summarize by DomainName;\nlet DnsEvents =\n  relevantIdentityQueryEvents\n  | union\n  relevantDeviceNetworkEvents  \n  | union\n  relevantDeviceEvents\n  | summarize by DomainName;\nlet dictionary = dynamic([\"r\",\"q\",\"3\",\"g\",\"s\",\"a\",\"l\",\"t\",\"6\",\"u\",\"1\",\"i\",\"y\",\"f\",\"z\",\"o\",\"p\",\"5\",\"7\",\"2\",\"d\",\"4\",\"9\",\"b\",\"n\",\"x\",\"8\",\"c\",\"v\",\"m\",\"k\",\"e\",\"w\",\"h\",\"j\"]);\nlet regex_bad_domains =\n   AADSignInEventsBeta\n   //Collect domains from tenant from signin logs\n   | where Timestamp >= timeFrame\n   | extend domain = tostring(split(AccountUpn, \"@\", 1)[0])\n   | where domain != \"\"\n   | summarize by domain\n   | extend split_domain = split(domain, \".\")\n   //This cuts back on domains such as na.contoso.com by electing not to match on the \"na\" portion\n   | extend target_string = iff(strlen(split_domain[0]) <= 2, split_domain[1], split_domain[0])\n   | extend target_string = split(target_string, \"-\")  | mv-expand target_string\n   //Rip all of the alphanumeric out of the domain name\n   | extend string_chars = extract_all(@\"([a-z0-9])\", tostring(target_string))\n   //Guid for tracking our data\n   | extend guid = new_guid()//Expand to get all of the individual chars from the domain\n   | mv-expand string_chars\n   | extend chars = tostring(string_chars)\n   //Conduct computation to encode the domain as per actor spec\n   | extend computed_char = array_index_of(dictionary, chars)\n   | extend computed_char = dictionary[(computed_char + 4) % array_length(dictionary)] \n   | summarize make_list(computed_char) by guid, domain\n   | extend target_encoded = tostring(strcat_array(list_computed_char, \"\"))\n   //These are probably too small, but can be edited (expect FP's when going too small)\n   | where strlen(target_encoded) > 5\n   | distinct target_encoded\n   | summarize make_set(target_encoded)\n   //Key to join to DNS\n   | extend key = 1;\nDnsEvents\n  | extend key = 1\n  //For each DNS query join the malicious domain list\n  | join kind=inner (\n      regex_bad_domains\n  ) on key\n  | project-away key\n  //Expand each malicious key for each DNS query observed\n  | mv-expand set_target_encoded\n  //IndexOf allows us to fuzzy match on the substring\n  | extend match = indexof(DomainName, set_target_encoded)\n  | where match > -1\n```"
---

