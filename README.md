# New code to update MC to Planner integration

## Adding functions to also read SHD and Roadmap - Planned
## Future plans to create Teams meetings with action items (tasks)

This takes the idea that is implemented in R-CSA325 and uses the latest libraries for authentication to Graph.
I will be switching to also uses the AffectedWorkloadDisplayName field to get the products as this is now reliable
Initial work is just to change the process to create queue jobs per product, which can then be processed in one run through - rather than have a queue job per process.  This is more efficient, but the initial driver was an auth throttle
Tested and looking back 14 days should not exceed the queue max of 64K, and should process in under a minute