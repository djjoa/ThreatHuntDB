---
id: 3dbe65c4-c2ba-4139-9d7e-bf551d50d600
name: Make FolderPath Vogon Poetry
description: |
  This is a completely stupid and pointless query that makes Vogon poetry out
  of a random FolderPath from the table you pass it.  You can change
  DeviceProcessEvents for any table as long as it has a column named DeviceName
  and a column called FolderPath.  Feel free to check in more verses :)
  Don't know what Vogon poetry is?  You have a research assignment: http://tinyurl.com/y8ueqchl
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
tactics:
  - Creates Poetry
query: "```kusto\nlet MakeFolderPathVogonPoetry = (SourceData:(DeviceName:string, FolderPath:string)) {\n    let Verses = pack_array(\n        'My life was spent with PATH', \n        'Looking upon a barren PATH',\n        'Whilst in the distance I saw a PATH',\n        'Gazing at the PATH',\n        'It was quite the dreary PATH',\n        'As I sat alone in the PATH',\n        'It was such a beautiful PATH',\n        'Though I could choose only one PATH',\n        'While I longed for my PATH',\n        'I would never find PATH again',\n        'I hunt in PATH',\n        'The PATH my guide',\n        'The memory of PATH sings in my blood',\n        'I seize the PATH',\n        'I carry it to my PATH',\n        'And I lay my PATH at your feet'\n    );    \n    let PhraseCount = toscalar(array_length(Verses));\n    let CleanedSourceData = (\n        SourceData\n        | take 10000\n        | where isnotempty( FolderPath) and (FolderPath startswith \"/\" or FolderPath startswith \"c:\\\\\")\n        | project DeviceName, FolderPath\n    );\n    let RandRow = rand(toscalar(CleanedSourceData | count));\n    CleanedSourceData\n    | serialize \n    | where row_number() == RandRow\n    | extend Path = iff(FolderPath startswith \"/\", split(FolderPath, '/'), split(FolderPath, '\\\\'))\n    | where array_length( Path ) > 2\n    | mvexpand Path to typeof(string)\n    | where isnotempty(Path)\n    | extend Rand = toint(rand(PhraseCount))\n    | extend VerseTemplate = tostring(Verses[Rand])\n    | extend Verse = strcat(substring(VerseTemplate,0,indexof(VerseTemplate, 'PATH')), Path, substring(VerseTemplate, (indexof(VerseTemplate, 'PATH') + 4), (strlen(VerseTemplate) -  indexof(VerseTemplate, 'PATH') + 4))) \n    | serialize \n    | project DeviceName, FolderPath, Verse\n};\nDeviceProcessEvents\n| invoke MakeFolderPathVogonPoetry()\n```"
---

