# Input bindings are passed in via param block.
param([object] $message, $TriggerMetadata)
Write-Host "Number of keys is $($message.keys.count)"
# $in = Get-Content $message -Raw
# $messageCenterTask = $message | ConvertFrom-Json -AsHashtable
# $title = $messageCenterTask.title 

# Write out the queue message and insertion time to the information log.
Write-Host "PowerShell queue trigger function reading work item: $($message['description'])"
# Write-Host "What is in in $in"
Write-Host "Queue item insertion time: $($TriggerMetadata.InsertionTime)"



Import-Module "D:\home\site\wwwroot\MSAL\MSAL.PS.psd1"

$PWord = ConvertTo-SecureString -String $env:aadPassword -AsPlainText -Force
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $env:aadUsername, $PWord

$graphToken = Get-MsalToken -ClientId "5d310a05-d6f6-465b-8d46-9de192d8085c"  -AzureCloudInstance AzurePublic `
-TenantId "01ba1a71-c58f-48a6-bc02-5e697e4298e5" -Authority "https://login.microsoftonline.com/brismith.onmicrosoft.com" `
-UserCredential $Credential

# Write-Host $token.Scopes

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

Write-Host $messageCenterPlanTasksValue[0].id

<# 
#################################################
# Check if the task already exists by bucketId
#################################################
$taskExists = $FALSE
ForEach($existingTask in $messageCenterPlanTasksValue){
    if(($existingTask.title -match $messageCenterTask.id) -and ($existingTask.bucketId -eq $messageCenterTask.bucketId)){
    $taskExists = $TRUE
    Break
}
}


# Adding the task
if(!$taskExists){
    $setTask =@{}
    If($messageCenterTask.dueDate){
        #$setTask.Add("dueDateTime", ([DateTime]$messageCenterTask.dueDate))
        $setTask.Add("dueDateTime", $messageCenterTask.dueDate)
    }
    $setTask.Add("orderHint", " !")
    $messageCenterTask.title = $messageCenterTask.title -replace "â€™", "'"
    #$messageCenterTask.title = $messageCenterTask.title -replace "â€“", "-"
    $setTask.Add("title", $messageCenterTask.title)
    $setTask.Add("planId", $messageCenterPlanId)

    # Setting Applied Categories
$appliedCategories = @{}
if($messageCenterTask.categories -match 'Action'){
    $appliedCategories.Add("category1",$TRUE)
}
else{$appliedCategories.Add("category1",$FALSE)}
if($messageCenterTask.categories -match 'Plan for Change'){
    $appliedCategories.Add("category2",$TRUE)
}
else{$appliedCategories.Add("category2",$FALSE)}
if($messageCenterTask.categories -match 'Prevent or Fix Issues'){
    $appliedCategories.Add("category3",$TRUE)
}
else{$appliedCategories.Add("category3",$FALSE)}
if($messageCenterTask.categories -match 'Advisory'){
    $appliedCategories.Add("category4",$TRUE)
}
else{$appliedCategories.Add("category4",$FALSE)}
if($messageCenterTask.categories -match 'Awareness'){
    $appliedCategories.Add("category5",$TRUE)
}
else{$appliedCategories.Add("category5",$FALSE)}
if($messageCenterTask.categories -match 'Stay Informed'){
    $appliedCategories.Add("category6",$TRUE)
}
else{$appliedCategories.Add("category6",$FALSE)}

$setTask.Add("appliedCategories",$appliedCategories)

# Set bucket and assignee

$setTask.Add("bucketId", $messageCenterTask.bucketId)
$assignmentType = @{}
$assignmentType.Add("@odata.type","#microsoft.graph.plannerAssignment")
$assignmentType.Add("orderHint"," !")
$assignments = @{}
$assignments.Add($messageCenterTask.assignee, $assignmentType)
$setTask.Add("assignments", $assignments)

# Make new task call

$Request = @" 
$($setTask | ConvertTo-Json)
"@

$headers = @{}
$headers.Add('Authorization','Bearer ' + $graphToken.AccessToken)
$headers.Add('Content-Type', "application/json")
$headers.Add('Content-length', + $Request.Length)
$headers.Add('Prefer', "return=representation")
 
$newTask = Invoke-WebRequest -Uri "https://graph.microsoft.com/v1.0/planner/tasks" -Method Post -Body $Request -Headers $headers -UseBasicParsing
$newTaskContent = $newTask.Content | ConvertFrom-Json
$newTaskId = $newTaskContent.id


# Add task details
# Pull any urls out of the description to add as attachments
$myMatches = New-Object System.Collections.ArrayList
$myMatches.clear()
$messageCenterTask.description = $messageCenterTask.description -replace '&amp;', '&'
$regex = 'https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%_\+.~#?&//=]*)'
# Find all matches in description and add to an array
select-string -Input $messageCenterTask.description -Pattern $regex -AllMatches | % { $_.Matches } | % {     $myMatches.add($_.Value)}



#Replacing some forbidden characters for odata properties
$externalLink = $messageCenterTask.reference -replace '\.', '%2E'
$externalLink = $externalLink -replace ':', '%3A'
$externalLink = $externalLink -replace '\#', '%23'
$externalLink = $externalLink -replace '\@', '%40'
$messageCenterTask.description = $messageCenterTask.description -replace '[\u201C\u201D]', '"'
#$messageCenterTask.description = $messageCenterTask.description -replace "[”]", '' 
$messageCenterTask.description = $messageCenterTask.description -replace "â€œ", '"' 
$messageCenterTask.description = $messageCenterTask.description -replace "â€™", "'"
$messageCenterTask.description = $messageCenterTask.description -replace "â€", '"'
Write-Output $messageCenterTask.description
$setTaskDetails = @{}
$setTaskDetails.Add("description", $messageCenterTask.description)
if(($messageCenterTask.reference) -or ($myMatches.Count -gt 0)){
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
if($messageCenterTask.reference){
$references.Add($externalLink.trim(), $reference)
}
$setTaskDetails.Add("references", $references)
$setTaskDetails.Add("previewType", "reference")
}
Start-Sleep -s 2
#Get Current Etag for task details

$uri = "https://graph.microsoft.com/v1.0/planner/tasks/" + $newTaskId + "/details"

$result = Invoke-WebRequest -Uri $uri -Method GET -Headers $headers -UseBasicParsing
$freshEtagTaskContent = $result.Content | ConvertFrom-Json
 
$Request = @"
$($setTaskDetails | ConvertTo-Json)
"@

$headers = @{}
$headers.Add('Authorization','Bearer ' + $graphToken.AccessToken)
$headers.Add('If-Match', $freshEtagTaskContent.'@odata.etag')
$headers.Add('Content-Type', "application/json")
$headers.Add('Content-length', + $Request.Length)
Write-Output $Request
$uri = "https://graph.microsoft.com/v1.0/planner/tasks/" + $newTaskId + "/details"

$result = Invoke-WebRequest -Uri $uri -Method PATCH -Body $Request -Headers $headers -UseBasicParsing
} #>
Write-Output "PowerShell script processed queue message '$title'"