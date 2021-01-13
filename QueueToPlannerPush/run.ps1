# Input bindings are passed in via param block.
param([object] $message, $TriggerMetadata)

# Write out the queue message and insertion time to the information log.
Write-Host "PowerShell queue trigger function reading work item: $($message.product)"
Write-Host "PowerShell queue trigger function reading work item tasks: $($message.tasks.Keys)"
Write-Host "PowerShell queue trigger function reading work item type: $($message.GetType())"

# Write-Host "What is in in $in"
Write-Host "Queue item insertion time: $($TriggerMetadata.InsertionTime)"

# MSAL.PS added to the function to support the MSAL libraries
Import-Module "D:\home\site\wwwroot\MSAL\MSAL.PS.psd1"

$PWord = ConvertTo-SecureString -String $env:aadPassword -AsPlainText -Force
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $env:aadUsername, $PWord

$graphToken = Get-MsalToken -ClientId $env:clientId  -AzureCloudInstance AzurePublic `
-TenantId $env:tenantId -Authority "https://login.microsoftonline.com/$env:aadTenant" `
-UserCredential $Credential

$messageCenterPlanId = $env:messageCenterPlanId

#################################################
# Get tasks
#################################################

$headers = @{}
$headers.Add('Authorization','Bearer ' + $graphToken.AccessToken)
$headers.Add('Content-Type', "application/json")

$uri = "https://graph.microsoft.com/v1.0/planner/plans/" + $messageCenterPlanId + "/tasks"

$messageCenterPlanTasks = Invoke-WebRequest -Uri $uri -Method Get -Headers $headers -UseBasicParsing
$messageCenterPlanTasksContent = $messageCenterPlanTasks.Content | ConvertFrom-Json
$messageCenterPlanTasksValue = $messageCenterPlanTasksContent.value
$messageCenterPlanTasksValue = $messageCenterPlanTasksValue | Sort-Object bucketId, orderHint

#################################################
# Get individual tasks from the product message
#################################################

$message.tasks | ForEach-Object {
    $_.Keys
    $_.Values | ForEach-Object { $_.title
    # Do the task stuff here and create it
 
#################################################
# Check if the task already exists by bucketId
#################################################
$taskExists = $FALSE
ForEach($existingTask in $messageCenterPlanTasksValue){
    if(($existingTask.title -match $_.id) -and ($existingTask.bucketId -eq $_.bucketId)){
    $taskExists = $TRUE
    Break
}
}


# Adding the task
if(!$taskExists){
    $setTask =@{}
    If($_.dueDate){
        $setTask.Add("dueDateTime", $_.dueDate)
    }
    $setTask.Add("orderHint", " !")
    $_.title = $_.title -replace "â€™", "'"
    $setTask.Add("title", $_.title)
    $setTask.Add("planId", $messageCenterPlanId)

    # Setting Applied Categories
    # This will need to change/loop when more labels are supported (25)
$appliedCategories = @{}
if($_.categories -match 'Action'){
    $appliedCategories.Add("category1",$TRUE)
}
else{$appliedCategories.Add("category1",$FALSE)}
if($_.categories -match 'Plan for Change'){
    $appliedCategories.Add("category2",$TRUE)
}
else{$appliedCategories.Add("category2",$FALSE)}
if($_.categories -match 'Prevent or Fix Issues'){
    $appliedCategories.Add("category3",$TRUE)
}
else{$appliedCategories.Add("category3",$FALSE)}
if($_.categories -match 'Advisory'){
    $appliedCategories.Add("category4",$TRUE)
}
else{$appliedCategories.Add("category4",$FALSE)}
if($_.categories -match 'Awareness'){
    $appliedCategories.Add("category5",$TRUE)
}
else{$appliedCategories.Add("category5",$FALSE)}
if($_.categories -match 'Stay Informed'){
    $appliedCategories.Add("category6",$TRUE)
}
else{$appliedCategories.Add("category6",$FALSE)}

$setTask.Add("appliedCategories",$appliedCategories)

# Set bucket and assignee

$setTask.Add("bucketId", $_.bucketId)
$assignmentType = @{}
$assignmentType.Add("@odata.type","#microsoft.graph.plannerAssignment")
$assignmentType.Add("orderHint"," !")
$assignments = @{}
$assignments.Add($_.assignee, $assignmentType)
$setTask.Add("assignments", $assignments)

# Make new task call

$request = @" 
$($setTask | ConvertTo-Json)
"@

$headers = @{}
$headers.Add('Authorization','Bearer ' + $graphToken.AccessToken)
$headers.Add('Prefer', "return=representation")

$newTask = Invoke-WebRequest -Uri "https://graph.microsoft.com/v1.0/planner/tasks" -Method Post `
-Body $request -Headers $headers -UseBasicParsing `
-ContentType "application/json"
$newTaskContent = $newTask.Content | ConvertFrom-Json
$newTaskId = $newTaskContent.id

# Add task details
# Pull any urls out of the description to add as attachments
$myMatches = New-Object System.Collections.ArrayList
$myMatches.clear()
$_.description = $_.description -replace '&amp;', '&'
$regex = 'https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%_\+.~#?&//=]*)'
# Find all matches in description and add to an array
select-string -Input $_.description -Pattern $regex -AllMatches | % { $_.Matches } | % {$myMatches.add($_.Value)}
$myMatches = $MyMatches | Select-Object -Unique

#Replacing some forbidden characters for odata properties
$externalLink = $_.reference -replace '\.', '%2E'
$externalLink = $externalLink -replace ':', '%3A'
$externalLink = $externalLink -replace '\#', '%23'
$externalLink = $externalLink -replace '\@', '%40'
$_.description = $_.description -replace '[\u201C\u201D]', '"'
$_.description = $_.description -replace "â€œ", '"' 
$_.description = $_.description -replace "â€™", "'"
$_.description = $_.description -replace "â€", '"'

$setTaskDetails = @{}
$setTaskDetails.Add("description", $_.description)
if(($_.reference) -or ($myMatches.Count -gt 0)){
$reference = @{}
$reference.Add("@odata.type", "#microsoft.graph.plannerExternalReference")
$reference.Add("alias", "Additional Information")
$reference.Add("type", "Other")
$reference.Add('previewPriority', ' !')
$references = @{}
ForEach($myMatch in $myMatches){
$myMatch = $myMatch -replace '\.', '%2E'
$myMatch = $myMatch -replace ':', '%3A'
$myMatch = $myMatch -replace '\#', '%23'
$myMatch = $myMatch -replace '\@', '%40'
$references.Add($myMatch.trim(), $reference)
}
if($_.reference){
$references.Add($externalLink.trim(), $reference)
$references = $references | Select-Object -Unique
}
$setTaskDetails.Add("references", $references)
$setTaskDetails.Add("previewType", "reference")
}
Start-Sleep -s 4
#Get Current Etag for task details

$uri = "https://graph.microsoft.com/v1.0/planner/tasks/" + $newTaskId + "/details"

$result = Invoke-WebRequest -Uri $uri -Method GET -Headers $headers -UseBasicParsing
$freshEtagTaskContent = $result.Content | ConvertFrom-Json
 
$request = @"
$($setTaskDetails | ConvertTo-Json)
"@

$headers = @{}
$headers.Add('Authorization','Bearer ' + $graphToken.AccessToken)
$headers.Add('If-Match', $freshEtagTaskContent.'@odata.etag')

$uri = "https://graph.microsoft.com/v1.0/planner/tasks/" + $newTaskId + "/details"

$result = Invoke-WebRequest -Uri $uri -Method PATCH `
-Body $request -Headers $headers -UseBasicParsing `
-ContentType "application/json"

Write-Output "PowerShell script processed queue message $($_.id)"

}
# Next task
}
}

