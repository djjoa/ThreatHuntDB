---
id: 3661b3e6-be67-41af-a0c1-fa7c012f1233
name: StrRAT-Email-Delivery
description: |
  StrRAT is a Java-based remote access tool which steals browser credentials, logs keystrokes and take remote control of infected systems. It also has a module to download additional payload onto to the infected machine based on C2 server command. Additionally, this threat also has a ransomware encryption/decryption module which appends .crimson extension.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - EmailUrlInfo
tactics:
  - Initial access
query: |-
  ```kusto
  EmailUrlInfo
  | where UrlDomain has_any ('metroscaffingltg.co.uk',
  'pg-finacesolutions.co.uk',
  'jpfletcherconsultancy.co.uk',
  'buildersworlinc.co.uk',
  'bentlyconstbuild.co.uk',
  'alfredoscafeltd.co.uk',
  'zincocorporation.co.uk',
  'playerscircleinc.co.uk',
  'tg-cranedinc.co.uk',
  'adamridley.co.uk',
  'westcoasttrustedtaxis.co.uk',
  'sivospremiumclub.co.uk',
  'gossyexperience.co.uk',
  'jeffersonsandc.co.uk',
  'fillinaresortsltd.co.uk',
  'tk-consultancyltd.co.uk')
  ```
---
