# ThreatHuntDB
Aggregated "database" of threat hunting queries spanning multiple security solutions alligning to Mitre ATT&amp;CK Framework.



## Notes 

> Of the two links, the stix datasource is much larger. Mitre attacck techniques website says there's about 700 current techniques and sub-techniques but when filtering both datasets for non-depricated and non-revoked techniques and sub-techniques, I'm only getting around 357. 

"https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"


### Splunk API Json 

> common fields which will map to mitre navigation layers 

name, author, id, description, risk_score, search, datamodel, source, how_to_implement, known_false_positives



--------------

# worklog 

- filter by only OOTB hunt content 
- filter out `As part of content migration, this file is moved to new location` to get only true hunt content 
- 


---- 

# Github actions


```
# name: Refresh Feed
# on: [push]
# jobs:
#   refresh-feed:
#     runs-on: ubuntu-latest
#     steps:
#       - name: Checkout 🛎️
#         uses: actions/checkout@v2
#         with:
#           persist-credentials: false

#       - name: Fetch API Data 📦
#         uses: JamesIves/fetch-api-data-action@releases/v1
#         with:
#           ENDPOINT: https://www.loc.gov/maps/?fa=location:cyprus&fo=json&at=results
#           retry: true
#       - name: Build and Deploy 🚀
#         uses: JamesIves/github-pages-deploy-action@releases/v3
#         with:
#           ACCESS_TOKEN: ${{ secrets.REPO_TOKEN }}
#           BRANCH: master # Pushes the updates to the master branch.
#           FOLDER: fetch-api-data-action # The location of the data.json file saved by the Fetch API Data action.
#           TARGET_FOLDER: data # Saves the data into the 'data' directory on the master branch.
```

```
name: GitHub Self-Updating Repository Demo
on:
  workflow_dispatch
  
  # https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#schedule
  #schedule:
    # The shortest interval you can run scheduled workflows is once every 5 minutes.
    # Note: The schedule event can be delayed during periods of high loads of GitHub Actions workflow runs. 
    # High load times include the start of every hour. 
    # To decrease the chance of delay, schedule your workflow to run at a different time of the hour.
    # Every 5 minutes.
    # - cron: '*/5 * * * *'
    # At the beginning of every day.
    #- cron: "0 0 * * *"
    

# on: [push]

jobs:
  report:
    runs-on: ubuntu-latest
    steps:
      - name: Check out repository code
        # https://github.com/actions/checkout/tree/v3.0.2
        uses: actions/checkout@v3
      - name: Modify date and time
        run: |
          echo "Auto pulled content on $(date)" >> README.md
          cat README.md

      - name: Deploy 
        uses: JamesIves/github-pages-deploy-action@v4
        with: 
          branch: main # where you want to deploy
          commit-message: "testing deployment" #msg
          folder: data
          ssh-key: ${{ secrets.DEPLOY_KEY }} 
          
      # - name: Switch from HTTPs to SSH 
      #   run: git remote set-url origin ${{ secrets.ssh_url }}
        
      # - name: Push to repository
      #   run: |
      #     git config --global user.name "threathuntdb-actionbot"
      #     git config --global user.email threathuntdb-actionbot"@github.com"
      #     now=$(date)
      #     git add -A
      #     git commit -m "Auto Push on $now"
      #     git push
```


```
name: Secrets and Environment Variables
on: 
  workflow_dispatch

jobs: 
  top-secret: 
    runs-on: ubuntu-latest
    env: 
      DERP: ${{ vars.APP_ID }}

    steps: 
      - name: Read a variable 
        run: echo "Read a variable from the GitHub Actions > vars ${{ vars.APP_ID }}"

      - name: Tell me a secret (masked)! 
        run: echo "My APP_ID is value ${{ secrets.TEST_SECRET }}. (This will be masked)."

      - name: Missing secret
        run: echo "Unknown secret when not assigned ${{ secrets.DOES_NOT_EXIST }}"

      - name: Get repo name from github variable 
        run: echo "Repo name is ${{ github.repository }}" 

      - name: Read an env variable
        run: echo "My APP_ID value is ${{ env.DERP }} and once declared can be called with env.DERP OR $DERP (from within script)"

      - uses: actions/checkout@v2
      - name: Read the env from an external script
        run: |
          chmod +x .github/scripts/read_var.sh 
          .github/scripts/read_var.sh 
        shell: bash 

```

```
name: Manual test
on: workflow_dispatch

jobs:
    do-something: 
        runs-on: ubuntu-latest
        steps: 
            - run:  echo "Hello! I've been triggered manually."
```