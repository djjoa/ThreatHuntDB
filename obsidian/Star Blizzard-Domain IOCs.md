---
id: 4b14590a-a1f0-4756-9f3d-baafa696e051
name: Star Blizzard-Domain IOCs
description: |
  'This query identifies matches based on domain IOCs related to Star Blizzard against Microsoft Defender for Endpoint device network connections'
severity: High
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceNetworkEvents
tactics:
  - InitialAccess
relevantTechniques:
  - T1566
query: "```kusto\nlet IOCs_Domains = pack_array(\"cache-dns.com\",\"cache-dns-forwarding.com\",\"cache-dns-preview.com\",\"cache-docs.com\",\"cache-pdf.com\",\"cache-pdf.online\",\"cache-services.live\",\n                              \"cloud-docs.com\",\"cloud-drive.live\",\"cloud-storage.live\",\"docs-cache.com\",\"docs-forwarding.online\",\"docs-info.com\",\"docs-shared.com\",\n                              \"docs-shared.online\",\"docs-view.online\",\"document-forwarding.com\",\"document-online.live\",\"document-preview.com\",\"documents-cloud.com\",\n                              \"documents-cloud.online\",\"documents-forwarding.com\",\"document-share.live\",\"documents-online.live\",\"documents-pdf.online\",\"documents-preview.com\",\n                              \"documents-view.live\",\"document-view.live\",\"drive-docs.com\",\"drive-share.live\",\"goo-link.online\",\"hypertextteches.com\",\"mail-docs.online\",\n                              \"officeonline365.live\",\"online365-office.com\",\"online-document.live\",\"online-storage.live\",\"pdf-cache.com\",\"pdf-cache.online\",\"pdf-docs.online\",\n                              \"pdf-forwarding.online\",\"protection-checklinks.xyz\",\"protection-link.online\",\"protectionmail.online\",\"protection-office.live\",\"protect-link.online\",\n                              \"proton-docs.com\",\"proton-reader.com\",\"proton-viewer.com\",\"relogin-dashboard.online\",\"safe-connection.online\",\"safelinks-protect.live\",\"secureoffice.live\",                                \n                              \"webresources.live\",\"word-yand.live\",\"yandx-online.cloud\",\"y-ml.co\",\"docs-drive.online\",\"docs-info.online\",\"cloud-mail.online\",\"onlinecloud365.live\",\n                              \"pdf-cloud.online\",\"pdf-shared.online\",\"proton-pdf.online\",\"proton-view.online\",\"cloud-mail.online\",\"office365-online.live\",\"doc-viewer.com\",\n                              \"file-milgov.systems\",\"office-protection.online\");\nDeviceNetworkEvents \n| where RemoteUrl has_any(IOCs_Domains)\n```"
---

