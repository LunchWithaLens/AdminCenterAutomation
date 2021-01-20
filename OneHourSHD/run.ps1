# Input bindings are passed in via param block.
param($Timer)

# Get the current universal time in the default string format
$currentUTCtime = (Get-Date).ToUniversalTime()

# The 'IsPastDue' porperty is 'true' when the current function invocation is later than scheduled.
if ($Timer.IsPastDue) {
    Write-Host "PowerShell timer is running late!"
}

# Write an information log with the current time.
Write-Host "PowerShell timer trigger function ran! TIME: $currentUTCtime"

# BriSmith@Microsoft.com 
# Code to read M365 Message Cnter posts for specific products then make a Function call with the resultant json
# Will update to Graph calls once the Comms API swaps over

#Get the products we are interested in
$channels = Get-Content 'D:\home\site\wwwroot\OneHourSHD\teamChannels.json' | Out-String | ConvertFrom-json

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

# MSAL.PS added to the function to support the MSAL libraries
Import-Module "D:\home\site\wwwroot\MSAL\MSAL.PS.psd1"

$PWord = ConvertTo-SecureString -String $env:aadPassword -AsPlainText -Force
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $env:aadUsername, $PWord

$graphToken = Get-MsalToken -ClientId $env:clientId  -AzureCloudInstance AzurePublic `
-TenantId $env:tenantId -Authority "https://login.microsoftonline.com/$env:aadTenant" `
-UserCredential $Credential

$cutoff = (Get-Date).AddDays(-2)

ForEach($channel in $channels){
    # Get existing messages for the channel to see if we need to reply or create new
    $teamId = $channel.teamId
    $teamChannelId = $channel.teamChannelId
    $headers = @{}
    $headers.Add('Authorization','Bearer ' + $graphToken.AccessToken)
    # It seems to only work without a 403 on the beta endpoint...
    $uri = "https://graph.microsoft.com/beta/teams/" + $teamId + "/channels/" + $teamChannelId + "/messages"

    $existingMessages = Invoke-WebRequest -Uri $uri -Method Get `
        -Headers $headers -UseBasicParsing `
        -ContentType "application/json"

    $existingMessagesContent = $existingMessages.Content | ConvertFrom-Json
    $existingMessagesContentValues = $existingMessagesContent.value

    # Really just for debug use - check in the inner loop for reply or new
    # ForEach($existingChannelMessages in $existingMessagesContentValues){
    #    Write-Host $existingChannelMessages.id
    #    Write-Host $existingChannelMessages.subject
    # }

    :parentloop ForEach($message in $messages.Value){
        $reply = $false
        If([DateTime]$message.LastUpdatedTime -gt $cutoff){
            If($message.MessageType -eq 'Incident'){
                If($message.WorkloadDisplayName -match $channel.product){
                    
                $fullMessage = '<at id=\"0\">' + $channel.contactName + '</at> - '
                ForEach($messagePart in $message.Messages){
                    $fullMessage += $messagePart.MessageText
                    }
                $setBody = @{}
                $setBody.Add("contentType", "html")
                $setBody.Add("content", $fullMessage)

                $userDetail = @{}
                $userDetail.Add("displayName", $channel.contactName)
                $userDetail.Add("id", $channel.contactAad)
                $userDetail.Add("userIdentityType", "aadUser")

                $user = @{}
                $user.Add("user", $userDetail)

                $mentions = @()
                $mentions += (@{
                id = 0;
                mentionText = $channel.contactName;
                mentioned = $user;
                })
                
                $setPost = @{}
                $setPost.Add("importance", "high")
                $setPost.Add("subject", $message.Id + " " + $message.Status + " " + $channel.product + " " + $message.Title)    
                $SetPost.Add("body",$setBody)
                $setPost.Add("mentions",$mentions)
                $request = @"
$($setPost | ConvertTo-Json -Depth 4)
"@
                $request = $request.Replace("\\\", "\")
                # Write-Host $request
                # $teamId = $channel.teamId
                # $teamChannelId = $channel.teamChannelId
                $headers = @{}
                $headers.Add('Authorization','Bearer ' + $graphToken.AccessToken)
                # $headers.Add('If-Match', $freshEtagTaskContent.'@odata.etag')

                ForEach($existingChannelMessages in $existingMessagesContentValues){
                    # Write-Host $existingChannelMessages.id
                    # Write-Host $existingChannelMessages.subject
                    If($existingChannelMessages.subject){
                        If($existingChannelMessages.subject.Contains($message.Id)){
                        $reply = $true
                        $uri = "https://graph.microsoft.com/beta/teams/" + $teamId + "/channels/" + $teamChannelId + "/messages/" + $message.Id + "/replies"

                        $result = Invoke-WebRequest -Uri $uri -Method Post `
                            -Body $request -Headers $headers -UseBasicParsing `
                            -ContentType "application/json"
                        Write-Output "PowerShell script processed queue message REPLY " $message.id
                        break parentloop
                    } else {
                    $reply = $false
                    $uri = "https://graph.microsoft.com/v1.0/teams/" + $teamId + "/channels/" + $teamChannelId + "/messages/"

                    $result = Invoke-WebRequest -Uri $uri -Method Post `
                        -Body $request -Headers $headers -UseBasicParsing `
                        -ContentType "application/json"
                        Write-Output "PowerShell script processed queue message NEW " $message.id
                    }
                    
                }
                }
                             
                }
            }
        }
    }
}