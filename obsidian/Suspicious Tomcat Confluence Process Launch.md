---
id: 500e4cf1-9c25-4dfa-88f1-a23d95407e35
name: Suspicious Tomcat Confluence Process Launch
description: |
  The query checks for suspicious Tomcat process launches associated with likely exploitation of Confluence - CVE-2022-26134
  Read more here:.
  https://confluence.atlassian.com/doc/confluence-security-advisory-2022-06-02-1130377146.html
  https://nvd.nist.gov/vuln/detail/CVE-2022-26134
  Tags: #exploit #CVE-2022-26134
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
tactics:
  - Execution
  - Privilege Escalation
relevantTechniques:
  - T1203
query: "```kusto\nDeviceProcessEvents\n| where InitiatingProcessFileName hasprefix \"tomcat\" and InitiatingProcessCommandLine has \"confluence\"\n| where (ProcessCommandLine has_any(\"certutil\", \"whoami\", \"nltest\", \" dir \", \"curl\", \"ifconfig\", \"cat \", \"net user\",\n\"net time /domain\",\"tasklist\",\"-c ls\",\"ipconfig\",\"arp\",\"ping\",\"net view\",\"net group\",\"netstat\", \"wmic datafile\"))\nor (FileName =~ \"powershell.exe\" and ProcessCommandLine hasprefix \"-e\") \n```"
---
