#!/usr/bin/bash
# tested and working
# This script combs through the Azure Sentinel GitHub repository and 
# excludes any files that are listed for migration. 

# IDEAS 
# - use github code search to only poll updated hunt files that pass the viability logic chheck 
# - index a list of hashes to reference if YAML should be parsed from the new files


#TODO convert to github action 
# find all paths that shouldn't be queried (these contain rubbish)
# find Azure-Sentinel -type f -path "*Hunt*" -name "*.yaml" -exec grep "s part of content migration" -l {} ";" > azure-migration-ignore-paths.txt

#TODO conver to github action 
# find paths to all existing hunt content 
# find Azure-Sentinel -type f -path "*Hunt*" -name "*.yaml"  > azure-all-hunt-paths.txt

#TODO conver to github action 
# diff the ignored paths against content to get all viable hunt queries
#comm -3 <(sort azure-all-hunt-paths.txt ) <(sort azure-migration-ignore-paths.txt ) > azure-filtered-hunts.txt


##### PHASE 1 : Copy all viable content from Azure Hunts and write the YAML out to markdown 
#               files for obsidian post-processing


# # WARNING: no validation exists to check if the file is already there. Might not want to udpate it. Also wastes resources. 
# IFS=$'\n'
# time while read -r line # loop takes 0m11.783s
# do 
#     # get the "name" YAML key from each file to name appropriately 
#     hunt_name=$( perl -nle'print $& while m{(?<=^name: )(.*)(?=$)}g'  $line | tr '[' '(' | tr ']' ')' | tr -d '\r' | sed 's/\// and /g' )
#     # build the output file name 
#     OUT_FILE="obsidian/$hunt_name.md"
#     # write YAML data from Azure hunts to .md files for obsidian
#     cat $line > $OUT_FILE

# done <azure-filtered-hunts.txt

##### PAHSE 2: encase all `query` YAML keys in kusto codeblocks so they look pretty in obsidian 

# old=$(cat obsidian/test.md | yq e '.query'
# new=$(sed -e '$ a \`\`\`' -e '1 i \`\`\`kusto'  <(echo $old)) # wrapps query in kusto codeblock
# yq  ".query = \"$new\"" obsidian/test.md

while IFS= read -r line
do 
    old=$( yq e '.query' "$line")
    new=$(sed -e '$ a \`\`\`' -e '1 i \`\`\`kusto'  <(echo $old)) # wrapps query in kusto codeblock
    yq  ".query = \"$new\"" "$line"

done < <(find obsidian -type f)


# This will work to wrap all files with ---\ncontent\n--- but windows permissions prevent it from running. 
# will manually edit in VSCode for now but need to test this command with the github action 
# OPTION 1 
    #find obsidian -type f -name "*.md" -exec sed -i -e '1 i  ---' -e '$ a ---\n' {} ";"
# OPTION 2 
    # while read file ; do sed  -e '1 i  ---' -e '$ a ---\n' $file  ; done <  <(ls *.md)
# OPTION 3 (worked best )
    # 1 - sed -i -e '1 i  ---' *
    # 2:  sed -i -e "$ a ---\n" *


# this query is working with yq only 
# yq eval '.query as $old| .query |= "```kusto\n"+$old+"```"' obsidian/* 


# This yq query converts all single-lined strings into multi-lined strings. Will need this 
# for proper formatting in the Obsidian vault 
# yq ' (.query |= sub(" \n", "\n")) as $old | .query |=  $old' obsidian/*

# Worked semi-well at wrapping the frontmatter (sed --- before and after) in kusto blocks 
# NOTE : ran into issues with this because ---\nquery: null would be added to every line
#yq --front-matter process '(.query as $old) | .query |= "```kusto\n"+$old+"```" ' *.md

# THIS IS WHAT I USED AS THE SOLUTION TO WRAP CODEBLOCKS. WORKED JUST FINE. 
# find . -type f -name "*.md" -exec yq eval --front-matter=process --inplace '(.query as $old) | .query |= "```kusto\n"+$old+"```" ' {} ';'