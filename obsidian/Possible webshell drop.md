---
id: 8f2a256f-c9f1-4f0a-941a-a5a131d4bf3b
name: Possible webshell drop
description: |
  This query searches for files with common web page content extensions created by IIS or Apache that could run arbitrary code. It includes a throttling mechanism to reduce false positive detections for web-based content management.
description-detailed: |
  This query looks for files created by IIS or Apache matching common web page content extensions which
  can be used to execute arbitrary code.
  The query uses a throtlling mechanism in an attempt to avoid false positive detections for WebDAV or
  other web-based content management which might run under the context of the webserver process. Consider
  increasing the value of MaxFileOperations based on your false positive detection tolerance, or set it
  to -1 to disable this feature.
  Additional extensions of interest are listed after ExtensionList. Again, consider including \ excluding
  these extensions based on your organization's use and tolerance of potential false positive detections.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceFileEvents
tactics:
  - Initial access
  - Execution
  - Persistence
query: "```kusto\nlet MaxFileOperations = 3; // This will attempt to hide WebDAV publish operations by looking for file operations less than 'x' in a 5 minute period\nlet MaxAge = ago(7d); // This is how far back the query will search\nlet ExtensionList = pack_array('asp','aspx','aar','ascx','ashx','asmx','c','cfm','cgi','jsp','jspx','php','pl');//,'exe','dll','js','jar','py','ps1','psm1','cmd','psd1','java','wsf','vbs') Commented ones may cause false positive detection - add at will\nlet IncludeTemp = false; // whether to include files that contain \\temp\\ in their path\nlet PossibleShells = DeviceFileEvents \n| where Timestamp  > MaxAge \n    and InitiatingProcessFileName in~('w3wp.exe','httpd.exe') \n    and (IncludeTemp or FolderPath  !contains @'\\temp\\')\n    and ActionType in ('FileCreated', 'FileRenamed', 'FileModified')\n| extend extension = tolower(tostring(split(FileName,'.')[-1]))\n    , TimeBin = bin(Timestamp, 5m)\n| where extension in (ExtensionList);\nPossibleShells\n| summarize count() by DeviceId, TimeBin\n| where MaxFileOperations == -1 or count_ < MaxFileOperations\n| join kind=rightsemi PossibleShells on DeviceId, TimeBin\n```"
version: 1.0.0
---

