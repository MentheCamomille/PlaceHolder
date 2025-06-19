KERNELDIR = /lib/modules/$(shell uname -r)/build
PWD = $(shell pwd)
obj-m = mult.o
mult-objs = kernel_test.o second.o

modules: $(OBJS)
	$(MAKE) -C $(KERNELDIR) M=$(PWD) $@ $^

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) $@ $^
