---
id: 0c068643-049c-4c10-8771-ef3865627aa2
name: ExecuteBase64DecodedPayload
description: |
  Process executed from binary hidden in Base64 encoded file.  Encoding malicious software is a.
  Technique to obfuscate files from detection.
  The first and second ProcessCommandLine component is looking for Python decoding base64.
  The third ProcesssCommandLine component is looking for the Bash/sh commandline base64 decoding tool.
  The fourth one is looking for Ruby decoding base64.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
query: "```kusto\nDeviceProcessEvents \n| where Timestamp > ago(14d) \n| where ProcessCommandLine contains \".decode('base64')\"\n        or ProcessCommandLine contains \".b64decode(\"\n        or ProcessCommandLine contains \"base64 --decode\"\n        or ProcessCommandLine contains \".decode64(\" \n| project Timestamp , DeviceName , FileName , FolderPath , ProcessCommandLine , InitiatingProcessCommandLine \n| top 100 by Timestamp \n```"
---

