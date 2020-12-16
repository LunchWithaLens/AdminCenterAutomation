# Input bindings are passed in via param block.
param([string] $QueueItem, $TriggerMetadata)

# Write out the queue message and insertion time to the information log.
Write-Host "PowerShell queue trigger function processed work item: $QueueItem"
Write-Host "Queue item insertion time: $($TriggerMetadata.InsertionTime)"

Import-Module "D:\home\site\wwwroot\MSAL\MSAL.PS.psd1"

$PWord = ConvertTo-SecureString -String $env:aadPassword -AsPlainText -Force
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $env:aadUsername, $PWord

$token = Get-MsalToken -ClientId "5d310a05-d6f6-465b-8d46-9de192d8085c"  -AzureCloudInstance AzurePublic `
-TenantId "01ba1a71-c58f-48a6-bc02-5e697e4298e5" -Authority "https://login.microsoftonline.com/brismith.onmicrosoft.com" `
-UserCredential $Credential

Write-Host $token.Scopes