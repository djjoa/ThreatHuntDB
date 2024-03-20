---
id: d868871c-bdd6-45e9-9e9d-e3c4521654a7
name: oceanlotus-apt32-files
description: |
  This query was originally published in a threat analytics report about the group known to other security researchers as APT32 or OceanLotus
  This tracked activity group uses a wide array of malicious documents to conduct attacks. Some of their favorite techniques include sideloading dynamic link libraries,  and disguising payloads as image files. The group has weaponized files with exploits for the following vulnerabilities:
  1. CVE-2017-11882 - Software update
  2. CVE-2017-0199 - Software update
  The following query detects known malicious files associated with the group's campaigns.
  See Detect malicious network activity associated with group known as "OceanLotus" for another query related to this group's activity.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceFileEvents
      - DeviceProcessEvents
tactics:
  - Execution
  - Persistence
  - Defense evasion
  - Discovery
  - Malware, component
query: "```kusto\nlet MaliciousFiles=pack_array(//'KerrDown Lure Documents',\n'b32b5f76e7386a65bd9220befb21e0c46d4084c4',\n'c9d6b6fa37ca3d8cb57248993bb7c8a8fcd1bc89',\n'bf127e2a526240c7e65f24c544dad820cebe6d88',\n'347f555857d56a5afd33cfa19f8b5c771eed2553',\n'26c86c777fc074f5bbad27084bcb3bbc7afff88e',\n'872d2f4ccc43c08f73e84647b3098ff044cdfb75',\n'fb20427d0ac3cd4542755168886a96bde04c4f81',\n//'KerrDown Malware Downloader',\n'5f42b1771ce97679df78713292838c830e606e48',\n'72571ea4389af7a3a0e04d87327427d199f1d178',\n'3f2a7b5605262d8aa189c32a049756c6bfed589b',\n'220ea47d692afc196b5b913a9693323fd51f00f5',\n'85021e711d5c7d5bd968f6dfed7102ab4d8828e8',\n'c9e101c77f67203dfef66d21f2fa6c8765a6c649',\n'3182141a8255baa5b82c0953dd4541c6f9f26a03',\n'2d92d6459ef83ddf006bff4046b1bab86161a26b',\n'6aef7916f1c5d1886db06fe2d4bf35614a0b921f',\n'edd306617f1c7390a6bc067d3e8dfb44ac57287c',\n'd8cd8068cb30605646258c7a0d9b47e00eac28c5',\n'36422fe35473cc28a14701e5d9dcff4c2426d0ae',\n//'OceanLotus Documents Exploiting CVE-2017-11882',\n'd1357b284c951470066aaa7a8228190b88a5c7c3',\n'49dff13500116b6c085c5ce3de3c233c28669678',\n'9df3f0d8525edf2b88c4a150134c7699a85a1508',\n'50a755b30e8f3646f9476080f2c3ae1347f8f556',\n'bb060e5e7f7e946613a3497d58fbf026ae7c369a',\n'e2d949cf06842b5f7ae6b2dffaa49771a93a00d9',\n'OceanLotus Malicious SFX Files',\n'ac10f5b1d5ecab22b7b418d6e98fa18e32bbdeab',\n'cd13210a142da4bc02da47455eb2cfe13f35804a',\n'b4e6ddcd78884f64825fdf4710b35cdbeaabe8e2',\n'cc918f0da51794f0174437d336e6f3edfdd3cbe4',\n'8b991d4f2c108fd572c9c2059685fc574591e0be',\n'3dfc3d81572e16ceaae3d07922255eb88068b91d',\n//'OceanLotus OCX Dropper Files',\n'efac23b0e6395b1178bcf7086f72344b24c04dcc',\n'7642f2181cb189965c596964d2edf8fe50da742b',\n'377fdc842d4a721a103c32ce8cb4daf50b49f303',\n'bd39591a02b4e403a25aae502648264308085ded',\n'b998f1b92ed6246ded13b79d069aa91c35637dec',\n'83d520e8c3fdaefb5c8b180187b45c65590db21a',\n'b744878e150a2c254c867bad610778852c66d50a',\n'77c42f66dadf5b579f6bcd0771030adc7aefa97c',\n//'Malicious PNG Loader Files Used By OceanLotus ',\n'b58b7e8361e15fdc9fb21d0f7c26d5fc17241ff7',\n'5d5c1297415cc5746559182d91c9114700be07e2',\n'43191e81e1dcc9fac138fc1cc5e3aeb9b25cc1f4',\n//'Malicious DLL Files Used By OceanLotus ',\n'fa6be68b59b204c9f5ae886a888627a190491cf7',\n'20c3a72ff476aa1fb71367e1d5dd6e0eb166167e',\n'9d39e11f48b3ed4df35f5e19dd00b47764c98bdd',\n'81c1aff8589dc1e556f68562d7154377c745a1d5',\n'eb27eb72c4709d77db260b942d87ed486e271c93',\n'a28095221fbaad64af7a098e3dda80f6f426b1c2',\n'dabefa810a4febf4e7178df9d2ca2576333e04f2',\n'e716a98a4f0ebd366ff29bd9164e81e7c39a7789',\n'89abb3d70f200d480f05162c6877fab64941c5dd',\n//'OceanLotus Documents Exploiting CVE-2017-0199',\n'928b391af8e029dd8bef4f6dd82223b961429f0d',\n'295a99bebb8122a0fc26086ecc115582f37f6b47', \n'8b9fc2281a604a0ef2d56591a79f9f9397a6a2d2', \n'ec34a6b8943c110687ef6f39a838e68d42d24863', \n'd8be4f41886666687caf69533e11193e65e2a8e5', \n'd8be4f41886666687caf69533e11193e65e2a8e5', \n//'Malicious Documents Used By OceanLotus', \n'8b599ecdbec12a5bd76cf290f9297f13e8397d56', \n'c9073998d2a202e944f21e973448062af4fd29c0', \n'91510b97f764296b16fc88f0195cec6e6f1604af', \n'e00a4e0a03655dccff5ffdb4f4540115d820b5bb', \n'd39a7ecf844545363b96b8ee2eda9b76d51d602b', \n//'JEShell Malware Downloader', \n'8cad6621901b5512f4ecab7a22f8fcc205d3762b', \n'668572ba2aff5374a3536075b01854678c392c04'); \nunion DeviceFileEvents, DeviceProcessEvents \n| where Timestamp > ago(14d) \n| where SHA1 in(MaliciousFiles) or SHA1 in(MaliciousFiles)\n```"
---

