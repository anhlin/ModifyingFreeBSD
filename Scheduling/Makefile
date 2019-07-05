build:
	cp sys/kern/sched_ule.c sys/kern/kern_switch.c /usr/src/sys/kern 
	cd /usr/src && make buildkernel -DKERNFAST
	cd /usr/src && make installkernel
	reboot
