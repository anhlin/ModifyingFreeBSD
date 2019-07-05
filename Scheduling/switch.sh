#!/bin/sh
# Case 1 - Base Case
# Case 2 - Priority Queue
# Case 3 - Splatter 
# Case 4 - Splatter + Priority Queue

# User must be root to use script

if [ $1 -ge 1 -a $1 -le 4 ];  then
	sysctl -w kern.sched.sched_switch_case=$1
else
	echo "Error: case must be 1-4."
fi
