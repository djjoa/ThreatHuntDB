---
{
  "name": "Detect Risky SPL using Pretrained ML Model",
  "author": "Abhinav Mishra, Kumar Sharad, Namratha Sreekanta and Xiao Lin, Splunk",
  "date": "2022-06-16",
  "version": 1,
  "id": "b4aefb5f-1037-410d-a149-1e091288ba33",
  "description": "The following analytic uses a pretrained machine learning text classifier to detect potentially risky commands. The model is trained independently and then the model file is packaged within ESCU for usage. A command is deemed risky based on the presence of certain trigger keywords, along with the context and the role of the user (please see references). The model uses custom features to predict whether a SPL is risky using text classification. The model takes as input the command text, user and search type and outputs a risk score between [0,1]. A high score indicates higher likelihood of a command being risky. This model is on-prem only.",
  "splunk_tags": {
    "name": "Detect Risky SPL using Pretrained ML Model",
    "analytic_story": [
      "Splunk Vulnerabilities"
    ],
    "asset_type": "Web Server",
    "cis20": [
      "CIS 10"
    ],
    "kill_chain_phases": [
      "Installation"
    ],
    "mitre_attack_id": [
      "T1059"
    ],
    "nist": [
      "DE.AE"
    ],
    "observable": [
      {
        "name": "user",
        "type": "User",
        "role": [
          "Victim"
        ]
      }
    ],
    "message": "A potentially risky Splunk command has been run by $user$, kindly review.",
    "risk_score": 20,
    "security_domain": "audit",
    "risk_severity": "low",
    "mitre_attack_enrichments": [
      {
        "mitre_attack_id": "T1059",
        "mitre_attack_technique": "Command and Scripting Interpreter",
        "mitre_attack_tactics": [
          "Execution"
        ],
        "mitre_attack_groups": [
          "APT19",
          "APT32",
          "APT37",
          "APT39",
          "Dragonfly",
          "FIN5",
          "FIN6",
          "FIN7",
          "Fox Kitten",
          "Ke3chang",
          "OilRig",
          "Stealth Falcon",
          "Whitefly",
          "Windigo"
        ]
      }
    ]
  },
  "search": "```kusto\n| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Splunk_Audit.Search_Activity where Search_Activity.search_type=adhoc Search_Activity.user!=splunk-system-user by Search_Activity.search Search_Activity.user Search_Activity.search_type \n| eval spl_text = 'Search_Activity.search'. \" \" .'Search_Activity.user'. \" \" .'Search_Activity.search_type'\n| dedup spl_text \n| apply risky_spl_pre_trained_model \n| where risk_score > 0.5 \n| `drop_dm_object_name(Search_Activity)` \n| table search, user, search_type, risk_score \n| `detect_risky_spl_using_pretrained_ml_model_filter`\n```",
  "how_to_implement": "This detection depends on the MLTK app which can be found here - https://splunkbase.splunk.com/app/2890/ and the Splunk Audit datamodel which can be found here - https://splunkbase.splunk.com/app/1621/. Additionally, you need to be ingesting logs which include Search_Activity.search, Search_Activity.user, Search_Activity.search_type from your endpoints. The risk score threshold should be adjusted based on the environment. The detection uses a custom MLTK model hence we need a few more steps for deployment, as outlined here - https://gist.github.com/ksharad-splunk/be2a62227966049047f5e5c4f2adcabb.",
  "known_false_positives": "False positives may be present if suspicious behavior is observed, as determined by frequent usage of risky keywords.",
  "check_references": false,
  "references": [
    "https://docs.splunk.com/Documentation/Splunk/latest/Security/SPLsafeguards#Commands_that_trigger_the_warning"
  ],
  "datamodel": [
    "Splunk_Audit"
  ],
  "macros": [
    {
      "name": "security_content_summariesonly",
      "definition": "summariesonly=false allow_old_summaries=true fillnull_value=null",
      "description": "search data model's summaries only"
    },
    {
      "name": "detect_risky_spl_using_pretrained_ml_model_filter",
      "definition": "search *",
      "description": "Update this macro to limit the output results to filter out false positives."
    }
  ],
  "lookups": [],
  "source": "application"
}
---



```dataview
TABLE WITHOUT ID 
  search
where this.file.name = file.name 
```