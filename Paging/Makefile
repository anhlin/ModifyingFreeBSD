build:
	cp src/vm_page.c src/vm_pageout.c src/vm_phys.c /usr/src/sys/vm 
	cd /usr/src && make buildkernel -DKERNFAST
	cd /usr/src && make installkernel
	reboot
