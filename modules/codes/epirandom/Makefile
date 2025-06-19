KERNELDIR = /lib/modules/$(shell uname -r)/build
PWD = $(shell pwd)
obj-m = epirandom.o

modules:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) $@

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) $@
