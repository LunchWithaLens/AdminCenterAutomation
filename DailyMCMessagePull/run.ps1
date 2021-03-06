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
# When re-writing for MSAL I was hitting an exception getting throttled for too many auth calls
# Probably there was a way to avoid it, but decided rather than spawning many function calls
# I would bundle the messages by product as I should be able to create multiple tasks in 1 call efficiently.

$channel = [PSCustomObject]@{
}

# As many old posts sit around for a while and the queue limit is 64K I trimmed this to 14 days
# You could just keep 2 days as long as you were sure it ran each day.
$cutoff = (Get-Date).AddDays(-2)

ForEach($product in $products){
    $tasks = @{
    }
    ForEach($message in $messages.Value){
        If([DateTime]$message.LastUpdatedTime -gt $cutoff){
            If($message.MessageType -eq 'MessageCenter'){
                If($message.Title -match $product.product){
                $message.Title = $message.Title -replace '–', '-'       

                $fullMessage = ''
                ForEach($messagePart in $message.Messages){
                    $fullMessage += $messagePart.MessageText
                    }
                $task = [PSCustomObject]@{
                id = $message.Id
                title = $message.Id + ' - ' + $message.Title + ' - ' + $message.AffectedWorkloadDisplayNames
                categories = $message.ActionType + ', ' + $message.Classification + ', ' + $message.Category
                dueDate = $message.ActionRequiredByDate
                updated = $message.LastUpdatedTime
                afftectedWorkloadDisplayNames = $message.AffectedWorkloadDisplayNames
                description = $fullMessage
                reference = $message.ExternalLink
                product = $product.product
                bucketId = $product.bucketId
                assignee = $product.assignee
                    }
                $tasks.Add($message.id, $task)
                }
            }
        }
    }
    $channel = [PSCustomObject]@{
        product = $product.product
        tasks = $tasks
        }

    If($channel.tasks.count -gt 0){
        Write-Host $channel
        $outTask = (ConvertTo-Json $channel)
        Push-OutputBinding -Name outputQueueItem -Value $outTask
        }
       
 }  

