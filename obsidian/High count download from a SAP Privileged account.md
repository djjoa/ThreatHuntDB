---
id: 2843e796-3d6c-4a78-a815-1db783b346a3
name: High count download from a SAP Privileged account
description: |
  'This query detects high counts of download from a sensitive SAP Privileged account. A pre-built watchlist is leveraged to identify the privileged users that are under extra restrictions.'
description_detailed: "'This query detects high counts of download from a sensitive SAP Privileged account. A pre-built watchlist is leveraged to identify the privileged users that are under extra restrictions.\nReference: \n  https://learn.microsoft.com/en-us/azure/sentinel/sap/sap-solution-security-content#available-watchlists\n  https://techcommunity.microsoft.com/t5/azure-sentinel/what-s-new-watchlists-templates-are-now-in-public-preview/ba-p/2614340'\n"
requiredDataConnectors:
  - connectorId: SAP
    dataTypes:
      - SAPAuditLog
tactics:
  - InitialAccess
  - Exfiltration
relevantTechniques:
  - T1078
  - T1030
query: "```kusto\nlet priv_users = ('_GetWatchlist(\"VIPUsers\") | distinct [\"User Principal Name\"]');\nSAPAuditLog \n| where User in (priv_users)\n| where (MessageID in ('AU1') and Variable1 in ('A','H')) //AU1 = Logon Successful\n| where MessageText has \"Logon successful\"\n| project MessageID, LogonTypes=Variable1, ClientID, Email, User\n| join kind=inner \n(\nSAPAuditLog \n| where MessageID == \"AUY\" //AUY= Download bytes\n| extend ByteCount= toint(replace_string(replace_string(Variable1, \".\",\"\"), \",\",\"\")), Code=Variable2, Path= Variable3\n| summarize DownloadsByUser = count(), Paths= make_set(Variable3, 10), ByteCount=sum(ByteCount) by SystemID, ClientID, User, TerminalIPv6, Email, Host, TransactionCode, Instance\n| where ByteCount > 5000\n) on Email, User\n| project  User, Computer = Host, ClientID, Email, MessageID, LogonTypes, SystemID, ByteCount, DownloadsByUser, TerminalIPv6, TransactionCode\n| extend UserName = tostring(split(User, '@', 0)[0]), UPNSuffix = tostring(split(User, '@', 1)[0])\n| extend Account_0_Name = UserName\n| extend Account_0_UPNSuffix = UPNSuffix\n| extend IP_0_Address = TerminalIPv6\n| extend Host_0_HostName = Computer\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: UserName
      - identifier: UPNSuffix
        columnName: UPNSuffix
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: Computer
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: TerminalIPv6
version: 1.0.0
---

