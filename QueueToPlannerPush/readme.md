# Reading items from the queue and creating Planner tasks using PowerShell

The `QueueTrigger` makes it incredibly easy to react to new Queues inside of [Azure Queue Storage](https://azure.microsoft.com/en-us/services/storage/queues/).
In this case the queue gets messages from the DailyMCMessagePull function.

## How it works

As each message hits the queue the code runs and gets passed the message.  One part of this re-write was to update from ADAP to MSAL and I decided to use the [MSAL.PS PowerShell module](https://github.com/AzureAD/MSAL.PS/).  This makes the authentication to Graph quite straighforward.  Once authenticated it is just a case of first getting the existing tasks from the plan being used for message center posts and seeing if I already have the task in the plan.  I could handle this better, and certainly reducing the timespan would avoid too much overlap.  Once I identify a new task (they are bundled from the previous function into 1 or more tasks per product) then I need to make two calls to the Planner Graph API to first create the task and then update the task details.  I do a short wait between the calls - this might be handled better by coding a retry if the call to the details fails.  Much of the code involves formatting the request correctly and manipulating the data into the the right places.

For more information see the [Planner Graph API documentation](https://docs.microsoft.com/en-us/graph/api/resources/planner-overview?view=graph-rest-1.0)

<TODO> I do see some duplicate reference issues giving a key already added error sometimes, and have seen odd characters break things so have had to replace some characters.  I could also do better on the formating of the main description text. The new out of the box message center integration does a much better job of the text formatting, but I think there is still a potential need for a more flexible approach
