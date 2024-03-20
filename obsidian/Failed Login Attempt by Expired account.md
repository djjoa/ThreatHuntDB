---
id: 562900b1-39c4-4baf-a050-9cad1641db35
name: Failed Login Attempt by Expired account
description: "'This query looks at Account Logon events found through Windows Event Id's as well as SigninLogs to discover \nlogin attempts by accounts that have expired.'\n"
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - SigninLogs
  - connectorId: SecurityEvents
    dataTypes:
      - SecurityEvent
tactics:
  - InitialAccess
relevantTechniques:
  - T1078
query: "```kusto\n\n(union isfuzzy=true\n(SecurityEvent \n| where EventID == 4625\n//4625: An account failed to log on\n| where AccountType == 'User' \n| where SubStatus == '0xc0000193' \n| extend Reason = \ncase\n( SubStatus == '0xc0000193', 'Windows EventID (4625) - Account has expired', \"Unknown\")\n| project Computer, Account,  Reason , TimeGenerated\n),\n(\nSecurityEvent \n| where EventID == 4769\n//4769: A Kerberos service ticket was requested ( Kerberos Auth)\n| parse EventData with * 'Status\">' Status \"<\" *\n| parse EventData with * 'TargetUserName\">' TargetUserName \"<\" *\n| where Status == '0x12'\n| where TargetUserName !has \"$\" and isnotempty(TargetUserName)\n| extend Reason = \ncase(\nStatus == '0x12', 'Windows EventID (4769) - Account disabled, expired, locked out',\n'Unknown'), Account = TargetUserName \n| project Computer, Account, Reason , TimeGenerated\n),\n(\nSecurityEvent\n| where EventID == 4776 \n// 4776: The domain controller attempted to validate the credentials for an account ( NTLM Auth)\n| where Status == \"0xc0000193\"\n| extend Reason = \ncase(\nErrorCode == '0xc0000193', 'Windows EventID (4776) - Account has expired',\n'Unknown'), Account = TargetAccount \n| parse EventData with * 'Workstation\">' Workstation \"<\" *\n| extend Workstation = trim_start(@\"[\\\\]*\", Workstation)\n| extend Computer = iff(isnotempty(Workstation), Workstation, Computer ) \n| project Computer, Account, Reason , TimeGenerated\n) ,\n(\nSigninLogs \n| where ResultType == \"50057\" \n| extend Reason = \ncase(\nResultType == '50057', 'SigninLogs( Result Code- 50057) - User account is disabled. The account has been disabled by an administrator.',\n'Unknown'), Account = UserPrincipalName \n| project Account, Reason , TimeGenerated\n) )\n| summarize StartTimeUtc = min(TimeGenerated), EndTImeUtc = max(TimeGenerated), EventCount = count() by Computer, Account, Reason\n| extend timestamp = StartTimeUtc, AccountCustomEntity = Account, HostCustomEntity = Computer\n| order by EventCount desc \n```"
version: 1.0.1
metadata:
  source:
    kind: Community
  author:
    name: Shain
  support:
    tier: Community
  categories:
    domains: ["Security - Other", "Identity"]
---

