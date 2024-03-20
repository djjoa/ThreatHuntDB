---
id: 392533b7-a31a-488e-a553-5223811092de
name: Linux Agent Age Report
description: "This query uses the public MDE GitHub repo as a source to estimate the time that an agent build remains supported\nbased on the time it was uploaded. Please note that the timestamps used in this query are meant to estimate the\nsupport period and will likely not represent the actual expiration of the package which will be based on the build.\nIf you would like an estimate of support, uncomment the extend statement to get an idea of what is \\ is not \nsupported and an idea of how long support will remain for current agents.\nThis query currently only supports GA builds, not preview builds.\n"
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceTvmSoftwareInventory
query: "```kusto\nlet LinuxAgentVersions = \nexternaldata (data:string)[\"https://packages.microsoft.com/rhel/8/prod/\"]\n| parse kind=regex data with @'.*\">' Filename:string '</a>' Timestamp:datetime \" \" Size:int \n| where Filename startswith \"mdatp_\"\n| parse Filename with \"mdatp_\" Version:string \".x86_64.rpm\"\n| extend SoftwareVersion = strcat(Version, \".0\")\n// The below line should NOT be considered a statement of support, but rather a rough estimate. Uncomment to use.\n//| extend IsSupported = Timestamp > ago(270d), RemainingSupportInDays = 270 - datetime_diff('day', now(), Timestamp) \n| project-away data;\nDeviceTvmSoftwareInventory\n| where SoftwareName == \"defender_for_linux\"\n| project DeviceId, DeviceName, SoftwareVersion\n| lookup kind=leftouter (LinuxAgentVersions) on $left.SoftwareVersion == $right.SoftwareVersion\n```"
---

