---
id: 3c6038db-c915-42f3-b20e-22ac7ebb1182
name: Disabling Services via Registry
description: |
  Search for processes modifying the registry to disable security features.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
tactics:
  - Defense Evasion
query: "```kusto\nDeviceProcessEvents\n| where InitiatingProcessCommandLine has_all(@'\"reg\"', 'add', @'\"HKLM\\SOFTWARE\\Policies\\', '/v','/t', 'REG_DWORD', '/d', '/f')\n  and InitiatingProcessCommandLine has_any('DisableRealtimeMonitoring', 'UseTPMKey', 'UseTPMKeyPIN', 'UseAdvancedStartup', \n  'EnableBDEWithNoTPM', 'RecoveryKeyMessageSource')\n```"
---

