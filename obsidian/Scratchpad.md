# Appendix 



```dataview_
TABLE WITHOUT ID 
elink(tacticURL, tacticID) as Tactic,
tacticName,
elink(techniqueURL, techniqueID) as Technique,
techniqueName,
techniqueDescription,
split(techniquePlatforms, ", ") as "Observed Platforms",
split(techniqueDatasources, ", ") as "Observed Datasources",
defenses-bypassed,
permissions-required,
supports-remote,
system-requirements,
effective-permissions
from csv("attachments/mitreattack-python-v14-all-tactics-techniques.csv")
where  (
	contains(this.relevantTechniques, techniqueID)
	)
```

--------


```dataview_
TABLE WITHOUT ID 
elink(tacticURL, tacticID) as Tactic,
tacticName,
elink(techniqueURL, techniqueID) as Technique,
techniqueName,
techniqueDescription,
techniqueDetection,
techniquePlatforms,
techniqueDatasources,
defenses-bypassed,
permissions-required,
supports-remote,
system-requirements,
effective-permissions
from csv("attachments/mitreattack-python-v14-all-tactics-techniques.csv")
where  (
	contains(this.relevantTechniques, techniqueID)
	)
```
