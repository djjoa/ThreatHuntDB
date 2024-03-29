---
id: 056ceb9b-8f07-42b3-853e-ef3779de222e
name: Suspected Brute force attack Investigation
description: "'Summarize all the failures and success events for all users in the last 24 hours, \nonly identify users with more than 100 failures in the set period'\n"
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - SigninLogs
  - connectorId: AzureActiveDirectory
    dataTypes:
      - AADNonInteractiveUserSignInLogs
tactics:
  - CredentialAccess
relevantTechniques:
  - T1110
query: |-
  ```kusto
  let successCodes = dynamic(["0", "50125", "50140", "70043", "70044"]);
  let aadFunc = (tableName:string){
    table(tableName)
   | extend FailureOrSuccess = iff(ResultType in (successCodes), "Success", "Failure")
   | summarize FailureCount = countif(FailureOrSuccess=="Failure"), SuccessCount = countif(FailureOrSuccess=="Success") by bin(TimeGenerated, 1h),UserPrincipalName, UserDisplayName, IPAddress
   | where FailureCount > 100
   | where SuccessCount > 0
   | order by UserPrincipalName, TimeGenerated asc
   | extend AccountCustomEntity = UserPrincipalName, IPCustomEntity = IPAddress
  };
  let aadSignin = aadFunc("SigninLogs");
  let aadNonInt = aadFunc("AADNonInteractiveUserSignInLogs");
  union isfuzzy=true aadSignin, aadNonInt
  ```
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountCustomEntity
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPCustomEntity
---

