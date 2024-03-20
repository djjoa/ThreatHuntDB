---
id: fbcb7ff3-0d5a-4565-9caa-fc454138081f
name: devices_with_vuln_and_users_received_payload
description: |
  // Author: jan geisbauer
  // @janvonkirchheim
  // ---------------------  // 1.	A list of all devices that have this vulnerability
  // 2.	A list of all users that uses those devices
  // 3.	If these users received .mkv files recently
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceTvmSoftwareVulnerabilities
      - DeviceInfo
      - IdentityInfo
      - EmailAttachmentInfo
query: "```kusto\nlet all_computers_with_vlcvln=\nDeviceTvmSoftwareVulnerabilities \n| where SoftwareName contains \"vlc\" \n| summarize makelist(DeviceName, 200);\nlet all_affected_users=\nDeviceInfo\n| where DeviceName in (all_computers_with_vlcvln)\n| mvexpand todynamic(LoggedOnUsers)\n| extend ParsedFields = parsejson(LoggedOnUsers)\n| project UserName = ParsedFields.UserName\n| summarize makelist(tolower(UserName), 200);\nlet all_email_addresses_aff_users=\nIdentityInfo\n| where tolower(AccountName) in (all_affected_users)\n| summarize makelist(tolower(MailAddress), 200);\nEmailAttachmentInfo\n| where FileName contains \".mkv\"\n| where tolower(RecipientEmailAddress) in (all_email_addresses_aff_users)\n```"
version: 1.0.0
---

