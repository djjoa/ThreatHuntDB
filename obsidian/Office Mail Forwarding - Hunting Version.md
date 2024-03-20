---
id: d49fc965-aef3-49f6-89ad-10cc4697eb5b
name: Office Mail Forwarding - Hunting Version
description: |
  'Adversaries often abuse email-forwarding rules to monitor victim activities, steal information, and gain intelligence on the victim or their organization. This query highlights cases where user mail is being forwarded, including to external domains.'
description-detailed: "'Adversaries often abuse email-forwarding rules to monitor activities of a victim, steal information and further gain intelligence on\nvictim or victim's organization.This query over Office Activity data highlights cases where user mail is being forwarded and shows if \nit is being forwarded to external domains as well.'\n"
requiredDataConnectors:
  - connectorId: Office365
    dataTypes:
      - OfficeActivity (Exchange)
tactics:
  - Collection
  - Exfiltration
relevantTechniques:
  - T1114
  - T1020
query: "```kusto\nOfficeActivity\n| where OfficeWorkload == \"Exchange\"\n| where (Operation =~ \"Set-Mailbox\" and Parameters contains 'ForwardingSmtpAddress') \nor (Operation in~ ('New-InboxRule','Set-InboxRule') and (Parameters contains 'ForwardTo' or Parameters contains 'RedirectTo'))\n| extend parsed=parse_json(Parameters)\n| extend fwdingDestination_initial = (iif(Operation=~\"Set-Mailbox\", tostring(parsed[1].Value), tostring(parsed[2].Value)))\n| where isnotempty(fwdingDestination_initial)\n| extend fwdingDestination = iff(fwdingDestination_initial has \"smtp\", (split(fwdingDestination_initial,\":\")[1]), fwdingDestination_initial )\n| parse fwdingDestination with * '@' ForwardedtoDomain \n| parse UserId with *'@' UserDomain\n| extend subDomain = ((split(strcat(tostring(split(UserDomain, '.')[-2]),'.',tostring(split(UserDomain, '.')[-1])), '.') [0]))\n| where ForwardedtoDomain !contains subDomain\n| extend Result = iff( ForwardedtoDomain != UserDomain ,\"Mailbox rule created to forward to External Domain\", \"Forward rule for Internal domain\")\n| extend ClientIPAddress = case( ClientIP has \".\", tostring(split(ClientIP,\":\")[0]), ClientIP has \"[\", tostring(trim_start(@'[[]',tostring(split(ClientIP,\"]\")[0]))), ClientIP )\n| extend Port = case(\nClientIP has \".\", (split(ClientIP,\":\")[1]),\nClientIP has \"[\", tostring(split(ClientIP,\"]:\")[1]),\nClientIP\n)\n| project TimeGenerated, UserId, UserDomain, subDomain, Operation, ForwardedtoDomain, ClientIPAddress, Result, Port, OriginatingServer, OfficeObjectId, fwdingDestination\n| extend AccountName = tostring(split(UserId, \"@\")[0]), AccountUPNSuffix = tostring(split(UserId, \"@\")[1])\n| extend Host = tostring(split(OriginatingServer, \" (\")[0])\n| extend HostName = tostring(split(Host, \".\")[0])\n| extend DnsDomain = tostring(strcat_array(array_slice(split(Host, '.'), 1, -1), '.'))\n| extend Account_0_Name = AccountName\n| extend Account_0_UPNSuffix = AccountUPNSuffix\n| extend IP_0_Address = ClientIPAddress\n| extend Host_0_HostName = HostName\n| extend Host_0_DnsDomain = DnsDomain\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountName
      - identifier: UPNSuffix
        columnName: AccountUPNSuffix
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: ClientIPAddress
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostName
      - identifier: DnsDomain
        columnName: DnsDomain
version: 2.0.1
---

