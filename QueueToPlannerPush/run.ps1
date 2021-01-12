# Input bindings are passed in via param block.
param([object] $message, $TriggerMetadata)

# Write out the queue message and insertion time to the information log.
Write-Host "PowerShell queue trigger function reading work item: $($message.product)"
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

$messageCenterTasks = $message

$product = $messageCenterTasks.product
Write-Host "Product is $($product)"
$listOfMCs = ($messageCenterTasks.tasks | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name)

Write-Host "MCs are $($listOfMCs)"

ForEach($mcTask in ($messageCenterTasks.tasks | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name)){
    $mcMessage = $messageCenterTasks.tasks.$mcTask
Write-Host "Message is $($mcMessage)"
#################################################
# Check if the task already exists by bucketId
#################################################
$taskExists = $FALSE
ForEach($existingTask in $messageCenterPlanTasksValue){
    if(($existingTask.title -match $mcMessage.id) -and ($existingTask.bucketId -eq $mcMessage.bucketId)){
    $taskExists = $TRUE
    Break
}
}


# Adding the task
if(!$taskExists){
    $setTask =@{}
    If($mcMessage.dueDate){
        $setTask.Add("dueDateTime", $mcMessage.dueDate)
    }
    $setTask.Add("orderHint", " !")
    $mcMessage.title = $mcMessage.title -replace "â€™", "'"
    $setTask.Add("title", $mcMessage.title)
    $setTask.Add("planId", $messageCenterPlanId)

    # Setting Applied Categories
    # This will need to change/loop when more labels are supported (25)
$appliedCategories = @{}
if($mcMessage.categories -match 'Action'){
    $appliedCategories.Add("category1",$TRUE)
}
else{$appliedCategories.Add("category1",$FALSE)}
if($mcMessage.categories -match 'Plan for Change'){
    $appliedCategories.Add("category2",$TRUE)
}
else{$appliedCategories.Add("category2",$FALSE)}
if($mcMessage.categories -match 'Prevent or Fix Issues'){
    $appliedCategories.Add("category3",$TRUE)
}
else{$appliedCategories.Add("category3",$FALSE)}
if($mcMessage.categories -match 'Advisory'){
    $appliedCategories.Add("category4",$TRUE)
}
else{$appliedCategories.Add("category4",$FALSE)}
if($mcMessage.categories -match 'Awareness'){
    $appliedCategories.Add("category5",$TRUE)
}
else{$appliedCategories.Add("category5",$FALSE)}
if($mcMessage.categories -match 'Stay Informed'){
    $appliedCategories.Add("category6",$TRUE)
}
else{$appliedCategories.Add("category6",$FALSE)}

$setTask.Add("appliedCategories",$appliedCategories)

# Set bucket and assignee

$setTask.Add("bucketId", $mcMessage.bucketId)
$assignmentType = @{}
$assignmentType.Add("@odata.type","#microsoft.graph.plannerAssignment")
$assignmentType.Add("orderHint"," !")
$assignments = @{}
$assignments.Add($mcMessage.assignee, $assignmentType)
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
$mcMessage.description = $mcMessage.description -replace '&amp;', '&'
$regex = 'https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%_\+.~#?&//=]*)'
# Find all matches in description and add to an array
select-string -Input $mcMessage.description -Pattern $regex -AllMatches | % { $_.Matches } | % {     $myMatches.add($_.Value)}



#Replacing some forbidden characters for odata properties
$externalLink = $mcMessage.reference -replace '\.', '%2E'
$externalLink = $externalLink -replace ':', '%3A'
$externalLink = $externalLink -replace '\#', '%23'
$externalLink = $externalLink -replace '\@', '%40'
$mcMessage.description = $mcMessage.description -replace '[\u201C\u201D]', '"'
$mcMessage.description = $mcMessage.description -replace "â€œ", '"' 
$mcMessage.description = $mcMessage.description -replace "â€™", "'"
$mcMessage.description = $mcMessage.description -replace "â€", '"'

$setTaskDetails = @{}
$setTaskDetails.Add("description", $mcMessage.description)
if(($mcMessage.reference) -or ($myMatches.Count -gt 0)){
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
if($mcMessage.reference){
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

Write-Output "PowerShell script processed queue message '$title'"
}
}
