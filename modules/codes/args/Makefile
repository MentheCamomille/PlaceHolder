KERNELDIR = /lib/modules/$(shell uname -r)/build
PWD = $(shell pwd)
obj-m = args.o

modules: $(OBJS)
	$(MAKE) -C $(KERNELDIR) M=$(PWD) $@ $^

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) $@ $^
