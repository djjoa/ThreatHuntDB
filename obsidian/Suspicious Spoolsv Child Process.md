---
id: ece67992-9699-44f5-a5c5-f7e5c2d1d5d4
name: Suspicious Spoolsv Child Process
description: |
  Surfaces suspicious spoolsv.exe behavior likely related to CVE-2021-1675
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceImageLoadEvents
      - DeviceProcessEvents
tactics:
  - Privilege escalation
  - Exploit
query: "```kusto\n// Look for file load events for spoolsv\nDeviceImageLoadEvents\n| where Timestamp > ago(7d)\n| where InitiatingProcessFileName =~ \"spoolsv.exe\"\n| where FolderPath has @\"spool\\drivers\"\n| extend LoadFileTime = Timestamp\n| distinct DeviceId, LoadFileTime, FileName, SHA256\n// Join process data associated with spoolsv launching suspicious processes after image load\n| join DeviceProcessEvents on $left.DeviceId == $right.DeviceId\n| where Timestamp > ago(7d)\n| where Timestamp < LoadFileTime +5m\n| where InitiatingProcessFileName =~ \"spoolsv.exe\"\n| where ProcessIntegrityLevel =~ 'SYSTEM'\n| where (FileName1 in~(\"gpupdate.exe\", \"whoami.exe\", \"nltest.exe\", \"taskkill.exe\",\n            \"wmic.exe\", \"taskmgr.exe\", \"sc.exe\", \"findstr.exe\", \"curl.exe\", \"wget.exe\", \"certutil.exe\", \"bitsadmin.exe\", \"accesschk.exe\",\n            \"wevtutil.exe\", \"bcdedit.exe\", \"fsutil.exe\", \"cipher.exe\", \"schtasks.exe\", \"write.exe\", \"wuauclt.exe\") or \n// Processes with specific FPs removed          \n(FileName1 =~ \"net.exe\" and ProcessCommandLine !has \"start\") or \n(FileName1 =~ \"cmd.exe\" and not(ProcessCommandLine has_any(\".spl\", \"route add\", \"program files\"))) or \n(FileName1 =~ \"netsh.exe\" and not(ProcessCommandLine has_any(\"add portopening\", \"rule name\")))) or\n(FileName1 =~ \"powershell.exe\" and ProcessCommandLine!has \".spl\") or\n(FileName1 =~ \"rundll32.exe\" and ProcessCommandLine != \"\" and ProcessCommandLine !contains \" \")\n```"
---

