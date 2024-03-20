---
id: aaf84b80-7764-420c-98eb-239b5e194b3d
name: DNS Domains linked to WannaCry ransomware campaign
description: |
  'Displays the client DNS request for any of the known domains linked to WannaCry.
  These results may indicate a Wannacry/Wannacrypt ransomware infection.
  Reference: Domain listing from https://pastebin.com/cRUii32E'
requiredDataConnectors:
  - connectorId: DNS
    dataTypes:
      - DnsEvents
tactics:
  - Impact
relevantTechniques:
  - T1496
query: "```kusto\nlet badDomains = dynamic([\"agrdwrtj.us\", \"bctxawdt.us\", \"cokfqwjmferc.us\", \"cxbenjiikmhjcerbj.us\", \"depuisgef.us\", \"edoknehyvbl.us\", \n\"enyeikruptiukjorq.com\", \"frullndjtkojlu.us\", \"gcidpiuvamynj.us\", \"gxrytjoclpvv.us\", \"hanoluexjqcf.us\", \"iarirjjrnuornts.us\", \n\"ifbjoosjqhaeqjjwaerri.us\", \"iouenviwrc.us\", \"kuuelejkfwk.us\", \"lkbsxkitgxttgaobxu.us\", \"nnnlafqfnrbynwor.us\", \"ns768.com\", \n\"ofdwcjnko.us\", \"peuwdchnvn.us\", \"pvbeqjbqrslnkmashlsxb.us\", \"pxyhybnyv.us\", \"qkkftmpy.us\", \"rkhlkmpfpoqxmlqmkf.us\", \n\"ryitsfeogisr.us\", \"srwcjdfrtnhnjekjerl.us\", \"thstlufnunxaksr.us\", \"udrgtaxgdyv.us\", \"w5q7spejg96n.com\", \"xmqlcikldft.us\", \n\"yobvyjmjbsgdfqnh.us\", \"yrwgugricfklb.us\", \"ywpvqhlqnssecpdemq.us\"]);\nDnsEvents\n| where Name in~ (badDomains)\n| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), count() by Computer, ClientIP, WannaCrypt_Related_Domain = Name\n| extend HostName = iff(Computer has '.', substring(Computer,0,indexof(Computer,'.')),Computer)\n| extend DnsDomain = iff(Computer has '.', substring(Computer,indexof(Computer,'.')+1),\"\")\n| extend DNS_0_DomainName = WannaCrypt_Related_Domain\n| extend IP_0_Address = ClientIP\n| extend Host_0_HostName = HostName\n| extend Host_0_DnsDomain = DnsDomain\n```"
entityMappings:
  - entityType: DNS
    fieldMappings:
      - identifier: DomainName
        columnName: WannaCrypt_Related_Domain
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: ClientIP
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostName
      - identifier: DnsDomain
        columnName: DnsDomain
---

