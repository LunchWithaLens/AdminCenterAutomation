# Pulling Message Center posts using PowerShell

The `TimerTrigger` makes it incredibly easy to have your functions executed on a schedule. This sample demonstrates a simple use case of calling your function every 5 minutes.

## How it works

This uses an Azure function with a `TimerTrigger`.  The schedule is in the form of a [cron expression](https://en.wikipedia.org/wiki/Cron#CRON_expression)(See the link for full details). A cron expression is a string with 6 separate expressions which represent a given schedule via patterns. The pattern I've used represents a daily execution at 15:00 (3pm)  `0 0 15 * * *`. This, in plain text, means: "When seconds is equal to 0, minutes is equal to zero, at hour = 15:00, every day of the month, month, day of the week, or year".

The code then reads a json files that defines the products I'm interested in, who should be assigned the tasks for those products and to wich Planner bucket they need to be posted.  The code then authenticates to the tenant and reads the messages using the [Office 365 Service Communications API](https://docs.microsoft.com/en-us/office/office-365-management-api/office-365-service-communications-api-reference).  In the future I understand this API is moving to Graph.  

The main action happens in a loop for each product of interest that gets the recent messages, checks the MessageType to filter for Message Center posts (the same API gets incident information from the Service Health Dashboard too) then checks if the title contains the name of the product and if so it continues to build up a message to send to Azure queue storage that contains information for all the tasks for each product.

A To Do item here is to probably use the AffectedWorkloads information in the messages, which wasn't reliable when I wrote the first version of this code.
Also after doing the SHD stuff it might be useful to extend the product.json to support sriting the different product's tasks to different plans.

Once in the queue the trigger for the QueueToPlannerPush fires.
