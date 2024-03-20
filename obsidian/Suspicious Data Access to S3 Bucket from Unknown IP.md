---
id: 669e1338-b1a2-4d73-b720-a1e60d5d1474
name: Suspicious Data Access to S3 Bucket from Unknown IP
description: |
  'This query identifies unusual access to cloud storage, particularly from IPs not historically seen accessing the bucket or downloading files. It can be limited to private buckets with sensitive files by setting BucketName values.'
description_detailed: "'Adversaries may access data objects from improperly secured cloud storage. This query will identify any access originating from a Source IP which was not seen historically accessing the bucket or downloading files from it.\nYou can also limit the query to only private buckets with sensitive files by setting the value or list of values to BucketName column.\nRead more about ingest custom logs using Logstash at https://github.com/Azure/Azure-Sentinel/wiki/Ingest-Custom-Logs-LogStash \nand AWS S3 API GetObject at https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html and ListObject at https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjects.html\nand ListBucket at https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBuckets.html\nS3 LogStash Config: https://github.com/Azure/Azure-Sentinel/blob/master/Parsers/Logstash/input-aws_s3-output-loganalytics.conf\nS3 KQL Parser: https://aka.ms/AwsS3BucketAPILogsParser'\n"
requiredDataConnectors: []
tactics:
  - Collection
relevantTechniques:
  - T1530
query: "```kusto\n\nlet EventNameList = dynamic([\"ListBucket\",\"ListObjects\",\"GetObject\"]);\nlet starttime = todatetime('{{StartTimeISO}}');\nlet endtime = todatetime('{{EndTimeISO}}');\nlet lookback = starttime - 14d;\nAWSS3BucketAPILogParsed \n| where EventTime between(starttime..endtime)\n| where EventName in (EventNameList)\n| project EventTime, EventSource, EventName, SourceIPAddress, UserIdentityType, UserIdentityArn, UserIdentityUserName, BucketName, Host, AuthenticationMethod, SessionMfaAuthenticated, SessionUserName, Key\n| join kind=leftanti\n(\n  AWSS3BucketAPILogParsed \n  | where EventTime between (lookback..starttime)\n  | where EventName in (EventNameList)\n) on SourceIPAddress\n| summarize EventCount=count(), StartTimeUtc = min(EventTime), EndTimeUtc = max(EventTime), Files= makeset(Key), EventNames = makeset(EventName) by EventSource, SourceIPAddress, UserIdentityType, UserIdentityArn, UserIdentityUserName, BucketName, Host, AuthenticationMethod, SessionMfaAuthenticated, SessionUserName\n| project StartTimeUtc, EndTimeUtc, EventSource, Host, SourceIPAddress, UserIdentityType, BucketName, EventNames, Files, AuthenticationMethod, SessionMfaAuthenticated, SessionUserName, EventCount\n| extend timestamp = StartTimeUtc, HostCustomEntity = Host, AccountCustomEntity = SessionUserName, IPCustomEntity = SourceIPAddress\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountCustomEntity
  - entityType: Host
    fieldMappings:
      - identifier: FullName
        columnName: HostCustomEntity
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPCustomEntity
version: 1.0.1
---

