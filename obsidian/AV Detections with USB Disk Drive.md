---
id: 12198f2f-c53b-4617-8df8-120c66cbb373
name: AV Detections with USB Disk Drive
description: |
  This query make a best-guess detection regarding which removable media device caused an AV detection.
  The query is best run over 30 days to get the full USB history.
  Get a list of USB AV detections. This assumes any path not beginning with C is a removable/USB device.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceEvents
query: "```kusto\nlet usbDetections =\n    DeviceEvents\n    | where ActionType == \"AntivirusDetection\" and FolderPath !startswith \"c\" and FolderPath matches regex \"^[A-Za-z]{1}\"\n    | extend ParsedFields=parse_json(AdditionalFields)\n    | project DetectionTime=Timestamp, DeviceName, ThreatName=tostring(ParsedFields.ThreatName), FileName, FolderPath;\n//Get a list of USB disk drive connections, grouped by computer name and DeviceID\nlet usbConnections = \n    DeviceEvents\n    | where ActionType == \"PnpDeviceConnected\"\n    | extend parsed=parse_json(AdditionalFields)\n    | project Timestamp, DeviceName, DeviceId=tostring(parsed.DeviceId), ClassName=tostring(parsed.ClassName)\n    | where ClassName == \"DiskDrive\"\n    | summarize UsbFirstSeen=min(Timestamp), UsbLastSeen=max(Timestamp) by DeviceId, DeviceName;\n//Join USB AV detections and connections, where the detection occurs after the USB has been plugged in\nusbDetections | join kind=inner (usbConnections) on DeviceName | where DetectionTime > UsbFirstSeen and DetectionTime < UsbLastSeen\n| project DetectionTime, DeviceName, ThreatName, FileName, FolderPath, DeviceId, UsbFirstSeen, UsbLastSeen\n| sort by DetectionTime desc\n```"
---

