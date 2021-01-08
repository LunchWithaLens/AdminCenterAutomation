# Input bindings are passed in via param block.
param($Timer)

# Get the current universal time in the default string format
$currentUTCtime = (Get-Date).ToUniversalTime()

# The 'IsPastDue' property is 'true' when the current function invocation is later than scheduled.
if ($Timer.IsPastDue) {
    Write-Host "PowerShell timer is running late!"
}

# Write an information log with the current time.
Write-Host "PowerShell timer trigger function ran! TIME: $currentUTCtime"


# BriSmith@Microsoft.com 
# Code to read M365 Message Cnter posts for specific products then make a Function call with the resultant json
# Will update to Graph calls once the Comms API swaps over

#Get the products we are interested in
$products = Get-Content 'D:\home\site\wwwroot\DailyMCMessagePull\products.json' | Out-String | ConvertFrom-json

$tenantId = $env:tenantId
$client_id = $env:clientId
$client_secret = $env:secret

# Construct URI for OAuth Token
$uri = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"

# Construct Body for OAuth Token
$body = @{
    client_id     = $client_id
    scope         = "https://manage.office.com/.default"
    client_secret = $client_secret
    grant_type    = "client_credentials"
}

# Get OAuth 2.0 Token
$tokenRequest = try {

    Invoke-RestMethod -Method Post -Uri $uri -ContentType "application/x-www-form-urlencoded" -Body $body -ErrorAction Stop

}
catch [System.Net.WebException] {

    Write-Warning "Exception was caught: $($_.Exception.Message)"
   
}

$token = $tokenRequest.access_token

$messages = try {

    Invoke-RestMethod -Method Get -Uri "https://manage.office.com/api/v1.0/$tenantid/ServiceComms/Messages" -ContentType "application/json" -Headers @{Authorization = "Bearer $token"} -ErrorAction Stop

}
catch [System.Net.WebException] {

    Write-Warning "Exception was caught: $($_.Exception.Message)"
   
}

ForEach($product in $products){
    $channel = @{}
    $channel.Add('product', $product.product)
    ForEach($message in $messages.Value){
        If($message.MessageType -eq 'MessageCenter'){
            If($message.Title -match $product.product){
            $message.Title = $message.Title -replace '–', '-'       
            $task = @{}
            $task.Add('id', $message.Id)
            $task.Add('title',$message.Id + ' - ' + $message.Title + ' - ' + $message.AffectedWorkloadDisplayNames)
            $task.Add('categories', $message.ActionType + ', ' + $message.Classification + ', ' + $message.Category)
            $task.Add('dueDate', $message.ActionRequiredByDate)
            $task.Add('updated', $message.LastUpdatedTime)
            $task.Add('afftectedWorkloadDisplayNames', $message.AffectedWorkloadDisplayNames)
    
            $fullMessage = ''
            ForEach($messagePart in $message.Messages){
                $fullMessage += $messagePart.MessageText
            }
            $task.Add('description', $fullMessage)
            $task.Add('reference', $message.ExternalLink)
            $task.Add('product', $product.product)
            $task.Add('bucketId', $product.bucketId)
            $task.Add('assignee', $product.assignee)
        
    # $outTask = (ConvertTo-Json $task)
    # Write-Host $outTask
            $tasks += $task
    # Push-OutputBinding -Name outputQueueItem -Value $outTask
            }
            
            }
        
    }
    $channel = [PSCustomObject]@{
        product = $product.product
        tasks = $tasks
    }
$outTask = (ConvertTo-Json $channel)
Write-Host $outTask
$tasks = @{}
    }