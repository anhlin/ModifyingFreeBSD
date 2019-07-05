#!/bin/sh

sysctl vm.do_logging=1
stress --cpu 8 --io 4 --vm 2 --hdd 1 --timeout 10s
vmstat
sysctl vm.do_logging=0
