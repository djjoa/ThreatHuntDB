---
id: 37381608-bcd7-46bc-954e-1fd418023c26
name: Okta Login from multiple locations
description: |
  'This query identifies accounts associated with multiple authentications from different geographical locations in a short period of time.'
requiredDataConnectors:
  - connectorId: OktaSSO
    dataTypes:
      - Okta_CL
  - connectorId: OktaSSOv2
    dataTypes:
      - OktaSSO
tactics:
  - CredentialAccess
relevantTechniques:
  - T1110
tags:
  - Okta
query: "```kusto\nlet starttime = ago(4d);\nlet endtime =  ago(2d);\nlet common_locations = (OktaSSO\n  | where TimeGenerated between(starttime..endtime)\n  //| where eventType_s =~ 'user.session.start'\n  | extend locationString= strcat(client_geographicalContext_country_s, \"/\",client_geographicalContext_state_s, \"/\", client_geographicalContext_city_s)\n  | where locationString != \"//\"\n  | summarize count() by locationString\n  //modify the most common location value(below) based on your enviornment \n  | take 20\n  | project locationString);\nlet signIns = (OktaSSO\n  | where TimeGenerated between(starttime..endtime)\n // | where eventType_s =~ 'user.session.start'\n  | extend locationString= strcat(client_geographicalContext_country_s, \"/\",client_geographicalContext_state_s, \"/\", client_geographicalContext_city_s)\n  | where locationString != \"//\" and locationString !endswith \"/\"\n  | where locationString !in (common_locations));\n // Adjust these to tune your query\nlet lookupWindow = 10m;\nlet lookupBin = lookupWindow / 2.0; // lookup bin = equal to 1/2 of the lookup window\nlet threshold = 5;\nlet users = (signIns\n| summarize dcount(locationString) by actor_displayName_s\n| where dcount_locationString > threshold\n| project actor_displayName_s);\nsignIns\n  | where actor_displayName_s in (users)\n  | project-rename Start=TimeGenerated\n  | extend TimeKey = bin(Start, lookupBin)\n  | join kind = inner (\n  signIns\n  | project-rename End=TimeGenerated, EndLocationString=locationString\n    // TimeKey on the right side of the join - emulates this authentication appearing several times\n    | extend TimeKey = range(bin(End - lookupWindow, lookupBin),\n    bin(End, lookupBin), lookupBin)\n    | mvexpand TimeKey to typeof(datetime) // translate TimeKey arrange range to a column\n  ) on actor_displayName_s, TimeKey\n  | where End > Start\n  | project tostring(Start), tostring(End), locationString, EndLocationString, timeSpan = End - Start, actor_displayName_s, client_ipAddress_s, client_userAgent_rawUserAgent_s, client_userAgent_browser_s, client_device_s, displayMessage_s, outcome_result_s, outcome_reason_s, column_ifexists('debugContext_debugData_logOnlySecurityData_s', \"\"), debugContext_debugData_threatSuspected_s, client_geographicalContext_geolocation_lat_d, client_geographicalContext_geolocation_lon_d, eventType_s\n  | where locationString != EndLocationString\n  | summarize ips=make_set(client_ipAddress_s,100), UAs=make_set(client_userAgent_rawUserAgent_s,100) by timeSpan, actor_displayName_s, locationString, EndLocationString, Start, End, client_userAgent_rawUserAgent_s, client_userAgent_browser_s, client_device_s\n  | extend Account_0_Name = actor_displayName_s\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: actor_alternateId_s
      - identifier: DisplayName
        columnName: actor_displayName_s
version: 1.0.0
---

