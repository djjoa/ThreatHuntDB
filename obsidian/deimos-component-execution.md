---
id: 0e86928c-cc9f-494c-a79e-04f647eb5ef8
name: deimos-component-execution
description: |
  Jupyter, otherwise known as SolarMarker, is a malware family and cluster of components known for its info-stealing and backdoor capabilities that mainly proliferates through search engine optimization manipulation and malicious advertising in order to successfully encourage users to download malicious templates and documents. This malware has been popular since 2020 and currently is still active as of 2021.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceEvents
tactics:
  - Execution
  - Collection
  - Exfiltration
  - Impact
  - Malware, component
query: "```kusto\nDeviceEvents   \n| where InitiatingProcessFileName =~ \"powershell.exe\"\n| where ActionType == \"AmsiScriptContent\"\n| where AdditionalFields endswith '[mArS.deiMos]::inteRaCt()\"}'\n| project InitiatingProcessParentFileName, InitiatingProcessFileName, InitiatingProcessCommandLine, ActionType, AdditionalFields\n```"
---

