obj-m	+= rtl8xxxu.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

rtl8xxxu-y	:= rtl8xxxu_core.o rtl8xxxu_8192e.o rtl8xxxu_8723b.o \
		   rtl8xxxu_8723a.o rtl8xxxu_8192c.o rtl8xxxu_usb.o

default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) clean
