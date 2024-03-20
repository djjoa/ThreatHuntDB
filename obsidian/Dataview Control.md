---
dvSentinelQueryDetails: |
 ```dataview
 TABLE WITHOUT ID 
 	query as Query, 
 	tactics as Tactics, 
 	relevantTechniques as Techniques, 
 	severity as Severity
 where file.name = this.file.name 
 ```
dvSentinelRequirements: |
 ```dataview
 TABLE WITHOUT ID 
 	connectors.connectorId as "Required Connectors", 
 	dtypes as "Data Types"
 where file.name = this.file.name 
 flatten requiredDataConnectors as connectors
 flatten connectors.dataTypes as dtypes
 ```
dvSentinelEntityMappings: | 
 ```dataview
 TABLE WITHOUT ID 
 	Entity as "Entity Type",
 	flat(rows.entityMappings.fieldMappings.identifier,4) as "Entity Identifier" , 
 	flat(rows.entityMappings.fieldMappings.columnName,4) as "Mapped Column"
 where file.name = this.file.name
 group by (entityMappings.entityType) as Entity
 ```
dvSentinelMetadata: | 
 ```dataview
 TABLE WITHOUT ID 
 	version as Version, 
 	metadata.source.kind as Source, 
 	join(metadata.categories.domains, ", ") as "Security Domains", 
 	status as Status, 
 	kind as "Query Type (Vendor)"	
 where file.name = this.file.name
 ```
dvSentinelDetectionConsiderations: | 
  ```dataview
  TABLE WITHOUT ID 
  	elink(url, ID) as ID,
  	name as Name,
  	split(tactics, ", ") as Tactics,
  	detection as Detection,
  	split(platforms, ", ") as "Observed Platforms",
  	split(data-sources, ", ") as "Observed Datasources",
  	split(permissions-required, ", ") as "Permission Requirements",
  	supports-remote as "Remote?",
  	split(system-requirements, ", ") as "System Reqirements",
  	impact-type as Impact,
  	split(effective-permissions, ", ") as "Effective Permissions"
  from csv("attachments/mitreattack-python-v14-techniques.csv")
  where  (
  	contains(this.relevantTechniques, ID)
  	)
  ```
sentinelEvasionConsiderations: |
  ```dataview
  TABLE WITHOUT ID 
  elink(url, ID) as ID,
  name as Name,
  description as Description,
  split(platforms, ", ") as "Observed Platforms",
  split(data-sources, ", ") as "Observed Datasources",
  split(defenses-bypassed, ", ") as Bypasses,
  split(permissions-required, ", ") as "Permission Requirements",
  split(system-requirements, ", ") as "System Reqirements",
  split(effective-permissions, ", ") as "Effective Permissions"
  from csv("attachments/mitreattack-python-v14-techniques.csv")
  where  (
  contains(this.relevantTechniques, ID)
  )
  ```

---

