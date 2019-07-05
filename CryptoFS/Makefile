build:
	cp src/vfs_syscalls.c src/syscalls.master /usr/src/sys/kern
	cd /usr/src && make -C /sys/kern/ sysent
	cd /usr/src && make buildkernel -DKERNFAST
	cd /usr/src && make installkernel
	reboot
