---
id: 9e3fab4b-94dd-4cf9-b2aa-063d0fd25513
name: Multiple Explicit Credential Usage - 4648 events
description: |
  'Query identifies credential abuse across hosts, using Security Event 4648 to detect multiple account connections to various machines, indicative of Solorigate-like patterns.'
description-detailed: "'Based on recent investigations related to Solorigate, adversaries were seen to obtain and abuse credentials of multiple accounts \n to connect to multiple machines. This query uses Security Event 4648 (A logon was attempted using explicit credentials) \n to find machines in an environment, from where different accounts were used to connect to multiple hosts. Scoring is done based on \n protocols seen in Solorigate. While this mentions Solorigate, this hunting query can be used to identify this type of pattern for \n any attacker.\n Reference - https://docs.microsoft.com/windows/security/threat-protection/auditing/event-4648'\n"
requiredDataConnectors:
  - connectorId: SecurityEvents
    dataTypes:
      - SecurityEvent
  - connectorId: WindowsSecurityEvents
    dataTypes:
      - SecurityEvent
tactics:
  - Discovery
  - LateralMovement
relevantTechniques:
  - T1078
tags:
  - Solorigate
  - NOBELIUM
query: "```kusto\nlet WellKnownLocalSIDs = \"S-1-5-[0-9][0-9]$\";\nlet protocols = dynamic(['cifs', 'ldap', 'RPCSS', 'host' , 'HTTP', 'RestrictedKrbHost', 'TERMSRV', 'msomsdksvc', 'mssqlsvc']);\nSecurityEvent\n| where EventID == 4648\n| where SubjectUserSid != 'S-1-0-0' // this is the Nobody SID which really means No security principal was included.\n| where not(SubjectUserSid matches regex WellKnownLocalSIDs) //excluding system account/service account as this is generally normal\n| where TargetInfo has '/' //looking for only items that indicate an interesting protocol is included\n| where Computer !has tostring(split(TargetServerName,'$', 0)[0])\n| where TargetAccount !~ tostring(split(SubjectAccount,'$', 0)[0])\n| extend TargetInfoProtocol = tolower(split(TargetInfo, '/', 0)[0]), TargetInfoMachine = toupper(split(TargetInfo, '/', 1)[0])\n| extend TargetAccount = tolower(TargetAccount), SubjectAccount = tolower(SubjectAccount)\n| extend UncommonProtocol = case(not(TargetInfoProtocol has_any (protocols)), TargetInfoProtocol, 'NotApplicable')\n| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), AccountsUsedCount = dcount(TargetAccount), AccountsUsed = make_set(TargetAccount, 100), TargetMachineCount = dcount(TargetInfoMachine), \nTargetMachines = make_set(TargetInfoMachine, 100), TargetProtocols = dcount(TargetInfoProtocol), Protocols = make_set(TargetInfoProtocol, 100), Processes = make_set(Process, 100) by Computer, SubjectAccount, UncommonProtocol\n| where TargetMachineCount > 1 or UncommonProtocol != 'NotApplicable'\n| extend ProtocolCount = array_length(Protocols)\n| extend ProtocolScore = case(\n  Protocols has 'rpcss' and Protocols has 'host' and Protocols has 'cifs', 10, //observed in Solorigate and depending on which are used together the higher the score\n  Protocols has 'rpcss' and Protocols has 'host', 5,\n  Protocols has 'rpcss' and Protocols has 'cifs', 5,\n  Protocols has 'host' and Protocols has 'cifs', 5,\n  Protocols has 'ldap' or Protocols has 'rpcss' or Protocols has 'host' or Protocols has 'cifs', 1, //ldap is more commonly seen in general, this was also seen with Solorigate but not usually to the same machines as the others above\n  UncommonProtocol != 'NotApplicable', 3,\n  0 //other protocols may be of interest, but in relation to observations for enumeration/execution in Solorigate they receive 0\n)\n| extend Score = ProtocolScore + ProtocolCount + AccountsUsedCount\n| where Score >= 9 or (UncommonProtocol != 'NotApplicable' and Score >= 4) // Score must be 9 or better as this will include 5 points for atleast 2 of the interesting protocols + the count of protocols (min 2) + the number of accounts used for execution (min 2) = min of 9 OR score must be 4 or greater for an uncommon protocol\n| extend TimePeriod = EndTime - StartTime //This identifies the time between start and finish for the use of the explicit credentials, shorter time period may indicate scripted executions\n| project-away UncommonProtocol\n| extend timestamp = StartTime, NTDomain = split(SubjectAccount, '\\\\', 0)[0], Name = split(SubjectAccount, '\\\\', 1)[0], HostName = split(Computer, '.', 0)[0], DnsDomain = strcat_array(array_slice(split(Computer, '.'), 1, -1), '.')\n| order by Score desc\n| extend Account_0_Name = Name\n| extend Account_0_NTDomain = NTDomain\n| extend Host_0_HostName = HostName\n| extend Host_0_DnsDomain = DnsDomain   \n```"
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

