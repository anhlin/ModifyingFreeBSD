#!/bin/sh
# 0 - FreeBSD
# 1 - Bon Chance

if [ $1 -ge 0 -a $1 -le 1 ];  then
	sysctl -w vm.use_bon_chance=$1
else
	echo "Error: case must be 0 or 1."
fi
