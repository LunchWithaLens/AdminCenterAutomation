# New code to update MC to Planner integration

## Adding functions to also read SHD (Completed) and Roadmap (Still planned)
## Future plans to create Teams meetings with action items (tasks)

This takes the idea that is implemented in R-CSA325 and uses the latest MSAL libraries for authentication to Graph.
I will be switching to also uses the AffectedWorkloadDisplayName field to get the products as this is now reliable
Initial work is just to change the process to create queue jobs per product, which can then be processed in one run through - rather than have a queue job per process.  This is more efficient, but the initial driver was an auth throttling.
Tested and looking back 14 days should not exceed the queue max of 64K, and should process in under a minute

The $env variables needed which are not shared to Github are:

"AzureWebJobsStorage": "UseDevelopmentStorage=true",
"FUNCTIONS_WORKER_RUNTIME_VERSION": "~7",
"FUNCTIONS_WORKER_RUNTIME": "powershell",
"aadUsername": "exactly what it says",
"aadPassword": "this isn't may password - honestly",
"aadTenant": "the full .onmicrosoft tenant",
"clientId": "the client id configured in AAD app registration",
"messageCenterPlanId": "The plan ID that the message center posts will land in",
"tenantId": "the tenant GUID",
"secret": "the secret for the app registration",
"storageName_STORAGE": "the endpoint pointer for the queue"