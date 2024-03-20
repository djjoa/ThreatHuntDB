---
id: dd6fb889-43ef-44e1-a01d-093ab4bb12b2
name: Suspicious Enumeration using Adfind Tool
description: |
  'Query detects Adfind tool use for domain reconnaissance, regardless of executable name, focusing on DC and ADFS servers, to spot potential adversary activity.'
description-detailed: |
  Attackers can use Adfind which is an administrative tool to gather information about Domain controllers, ADFS Servers. They may also rename executables with other benign tools on the system.
  This query searches for Adfind usage in commandline arguments irrespective of executable name in short span of time. You can limit this query to your DC and ADFS servers.
  Below references talk about suspicious use of Adfind by adversaries.
  - https://thedfirreport.com/2020/05/08/adfind-recon/
  - https://www.fireeye.com/blog/threat-research/2020/05/tactics-techniques-procedures-associated-with-maze-ransomware-incidents.html
  - https://www.microsoft.com/security/blog/2020/12/18/analyzing-solorigate-the-compromised-dll-file-that-started-a-sophisticated-cyberattack-and-how-microsoft-defender-helps-protect/
requiredDataConnectors:
  - connectorId: SecurityEvents
    dataTypes:
      - SecurityEvent
  - connectorId: WindowsSecurityEvents
    dataTypes:
      - SecurityEvent
tactics:
  - Execution
  - Discovery
  - Collection
relevantTechniques:
  - T1059
  - T1087
  - T1482
  - T1201
  - T1069
  - T1074
tags:
  - Solorigate
  - NOBELIUM
query: "```kusto\n// Adjust lookupwindows for aggregate interval \nlet lookupwindow = 2m;\nlet threshold = 3; //number of commandlines in the set below\nlet DCADFSServersList = dynamic ([\"DCServer01\", \"DCServer02\", \"ADFSServer01\"]); // Enter a reference list of hostnames for your DC/ADFS servers\nlet tokens = dynamic([\"objectcategory\",\"domainlist\",\"dcmodes\",\"adinfo\",\"trustdmp\",\"computers_pwdnotreqd\",\"Domain Admins\", \"objectcategory=person\", \"objectcategory=computer\", \"objectcategory=*\"]);\nSecurityEvent\n//| where Computer in (DCADFSServersList) // Uncomment to limit it to your DC/ADFS servers list if specified above or any pattern in hostnames (startswith, matches regex, etc).\n| where EventID == 4688\n| where CommandLine has_any (tokens)\n| where CommandLine matches regex \"(.*)>(.*)\"\n| summarize Commandlines = make_set(CommandLine, 100), LastObserved=max(TimeGenerated) by bin(TimeGenerated, lookupwindow), Account, Computer, ParentProcessName, NewProcessName\n| extend Count = array_length(Commandlines)\n| where Count > threshold\n| extend NTDomain = split(Account, '\\\\', 0)[0], Name = split(Account, '\\\\', 1)[0], HostName = split(Computer, '.', 0)[0], DnsDomain = strcat_array(array_slice(split(Computer, '.'), 1, -1), '.')\n| extend Account_0_Name = Name\n| extend Account_0_NTDomain = NTDomain\n| extend Host_0_HostName = HostName\n| extend Host_0_DnsDomain = DnsDomain \n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: Name
      - identifier: NTDomain
        columnName: NTDomain
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostName
      - identifier: DnsDomain
        columnName: DnsDomain
version: 1.0.2
---
