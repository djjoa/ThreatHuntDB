---
id: f33abf94-6759-4820-9973-51d2a41749a4
name: Identify EUROPIUM IOCs
description: |
  The following query can locate activity possibly associated with the EUROPIUM threat actor
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceFileEvents
tactics:
  - Impact
query: "```kusto\nDeviceFileEvents \n| where SHA256 in (\"f116acc6508843f59e59fb5a8d643370dce82f492a217764521f46a856cc4cb5\",\"e1204ebbd8f15dbf5f2e41dddc5337e3182fc4daf75b05acc948b8b965480ca0\",\"bad65769c0b416bb16a82b5be11f1d4788239f8b2ba77ae57948b53a69e230a6\",\"bb45d8ffe245c361c04cca44d0df6e6bd7596cabd70070ffe0d9f519e3b620ea\",\"d1bec48c2a6a014d3708d210d48b68c545ac086f103016a20e862ac4a189279e\",\"fb49dce92f9a028a1da3045f705a574f3c1997fe947e2c69699b17f07e5a552b\",\"45bf0057b3121c6e444b316afafdd802d16083282d1cbfde3cdbf2a9d0915ace\",\"f8db380cc495e98c38a9fb505acba6574cbb18cfe5d7a2bb6807ad1633bf2df8\",\"7ad64b64e0a4e510be42ba631868bbda8779139dc0daad9395ab048306cc83c5\",\"cad2bc224108142b5aa19d787c19df236b0d12c779273d05f9b0298a63dc1fe5\",\"84be43f5830707cd421979f6775e9edde242bab98003644b3b491dbc08cc7c3e\")\n```"
---
