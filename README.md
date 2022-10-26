# Update M365 Message Center to Planner integration and new Service Health Dashboard to Teams

## Adding functions to also read Service Health Dashboard (Completed) and M365 Roadmap (Still planned)

## Future plans to create Teams meetings with action items (tasks)

## The MC pull now uses Graph - might be some bits still broken - need to fully test

This takes the idea that is implemented in R-CSA325 and uses the latest MSAL libraries for authentication to Graph. [MSAL.PS PowerShell module](https://github.com/AzureAD/MSAL.PS/)
I will be switching to also uses the AffectedWorkloadDisplayName field to get the products as this is now reliable
Initial work is just to change the process to create queue jobs per product, which can then be processed in one run through - rather than have a queue job per process.  This is more efficient, but the initial driver was an auth throttling.  
Tested and looking back 14 days should not exceed the queue max of 64K, and should process in under a minute

The $env variables needed which are not shared to Github are:

"AzureWebJobsStorage": "UseDevelopmentStorage=true",  
"FUNCTIONS_WORKER_RUNTIME_VERSION": "~7",  
"FUNCTIONS_WORKER_RUNTIME": "powershell",  
"aadUsername": "exactly what it says",  
"aadPassword": "this isn't my password - honestly",  
"aadTenant": "the full .onmicrosoft tenant",  
"clientId": "the client id configured in AAD app registration",  
"messageCenterPlanId": "The plan ID that the message center posts will land in",  
"tenantId": "the tenant GUID",  
"secret": "the secret for the app registration",  
"brismitho365mcr93ec_STORAGE": "the endpoint pointer for the queue"  

The Service Health Dashboard function also uses the same process and APIs, and writes to Teams channels as identified in a json file.  I may have a bug here - at times I've seen the same post multiple times.

Updated to Azure Functions project runtime ~4 and Azure Function Extensions 2.6.1+ to ensure continued support

ToDo: Add pull of Roadmap RSS feed and post to a SharePoint list
