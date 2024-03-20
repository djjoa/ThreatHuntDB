---
id: ae8a5c5d-4cfb-4a59-9adb-eb6c6c219620
name: Judgement Panda exfil activity
description: |
  Original Sigma Rule: https://github.com/Neo23x0/sigma/blob/master/rules/apt/apt_judgement_panda_gtr19.yml.
  Questions via Twitter: @janvonkirchheim.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
query: "```kusto\nDeviceProcessEvents\n| where Timestamp > ago(7d)\n| where ProcessCommandLine has @\"\\ldifde.exe -f -n \"\n     or ProcessCommandLine has @\"\\7za.exe a 1.7z \" \n     or ProcessCommandLine endswith @\" eprod.ldf\" \n     or ProcessCommandLine has @\"\\aaaa\\procdump64.exe\" \n     or ProcessCommandLine has @\"\\aaaa\\netsess.exe\" \n     or ProcessCommandLine has @\"\\aaaa\\7za.exe\" \n     or ProcessCommandLine has @\"copy .\\1.7z \\\" \n     or ProcessCommandLine has @\"copy \\client\\c$\\aaaa\\\" \n     or FolderPath == @\"C:\\Users\\Public\\7za.exe\"\n| top 100 by Timestamp desc\n```"
---

