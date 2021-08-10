# An hourly push of new Service Health messages to a Teams channel - PowerShell

The `TimerTrigger` makes it incredibly easy to have your functions executed on a schedule. In this case the timer runs every hour.

## How it works

For a `TimerTrigger` to work, you provide a schedule in the form of a [cron expression](https://en.wikipedia.org/wiki/Cron#CRON_expression)(See the link for full details). A cron expression is a string with 6 separate expressions which represent a given schedule via patterns. The pattern we use to represent every hour at 5 minutes after the hour is `0 5 * * * *`. This, in plain text, means: "When seconds is equal to 0, minutes is equal to 5, for any hour, day of the month, month, day of the week, or year".

The first part of the code is similar to the DailyMCMessagePull, and uses the ~~Office 365 Service Communications API~~ Graph API too, ~~but I am filtering for incidents,~~ and then rather than writing to a queue I am authenticating and making the Graph call to post to a Teams channel in the same function.  The reason for this choice is that the number of indcidents will be low so does not really justify pushing to the queue as the function will not take long.  I also use a json file to give me data about the products of interest, the Group and Teams channel to post to and also the person (name and aad GUID) so I can @mention in the post.

The bulk of the code is just going through the incidents then adding in the data for the specific product and formating the request to make the Graph call to Teams.  I just have a subject, importance and the content, along with a mention.  See the Teams [Create chatMessage documentation](https://docs.microsoft.com/en-us/graph/api/channel-post-message?view=graph-rest-1.0&tabs=http) for more details.

I will probably change the importance based on the message status - as resolved issues don't really need to be 'high'.
