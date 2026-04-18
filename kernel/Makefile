DEFAULT_HOST!=../default-host.sh
HOST?=DEFAULT_HOST
HOSTARCH!=../target-triplet-to-arch.sh $(HOST)

CFLAGS?=-O2 -g
CPPFLAGS?=
LDFLAGS?=
LIBS?=

DESTDIR?=
PREFIX?=/usr/local
EXEC_PREFIX?=$(PREFIX)
BOOTDIR?=$(EXEC_PREFIX)/boot
INCLUDEDIR?=$(PREFIX)/include

CFLAGS:=$(CFLAGS) -ffreestanding -Wall -Wextra
CPPFLAGS:=$(CPPFLAGS) -D__is_kernel -Iinclude
LDFLAGS:=$(LDFLAGS)
LIBS:=$(LIBS) -nostdlib -lk -lgcc

ARCHDIR=arch/$(HOSTARCH)

include $(ARCHDIR)/make.config

CFLAGS:=$(CFLAGS) $(KERNEL_ARCH_CFLAGS)
CPPFLAGS:=$(CPPFLAGS) $(KERNEL_ARCH_CPPFLAGS)
LDFLAGS:=$(LDFLAGS) $(KERNEL_ARCH_LDFLAGS)
LIBS:=$(LIBS) $(KERNEL_ARCH_LIBS)

KERNEL_OBJS=\
$(KERNEL_ARCH_OBJS) \
kernel/kernel.o \
kernel/process.o \
kernel/scheduler.o \

OBJS=\
$(ARCHDIR)/boot/crti.o \
$(ARCHDIR)/crtbegin.o \
$(KERNEL_OBJS) \
$(ARCHDIR)/crtend.o \
$(ARCHDIR)/boot/crtn.o \

LINK_LIST=\
$(LDFLAGS) \
$(ARCHDIR)/boot/crti.o \
$(ARCHDIR)/crtbegin.o \
$(KERNEL_OBJS) \
$(LIBS) \
$(ARCHDIR)/crtend.o \
$(ARCHDIR)/boot/crtn.o \

.PHONY: all clean install install-headers install-kernel
.SUFFIXES: .o .c .S

all: adhDOS.kernel

# Generate assembly offsets header
$(ARCHDIR)/asm_offsets.h: $(ARCHDIR)/gen_offsets.c include/kernel/process.h include/kernel/paging.h
	@echo "Generating assembly offsets..."
	@gcc -m32 -Iinclude -I../libc/include -o $(ARCHDIR)/gen_offsets $(ARCHDIR)/gen_offsets.c
	@$(ARCHDIR)/gen_offsets > $(ARCHDIR)/asm_offsets.h
	@rm -f $(ARCHDIR)/gen_offsets
	@echo "Generated $(ARCHDIR)/asm_offsets.h"

# Assembly files depend on offsets header
$(ARCHDIR)/cpu/idt_asm.o: $(ARCHDIR)/asm_offsets.h

adhDOS.kernel: $(OBJS) $(ARCHDIR)/linker.ld
	$(CC) -T $(ARCHDIR)/linker.ld -o $@ $(CFLAGS) $(LINK_LIST)
	grub-file --is-x86-multiboot adhDOS.kernel

$(ARCHDIR)/crtbegin.o $(ARCHDIR)/crtend.o:
	OBJ=`$(CC) $(CFLAGS) $(LDFLAGS) -print-file-name=$(@F)` && cp "$$OBJ" $@

.c.o:
	$(CC) -MD -c $< -o $@ -std=gnu11 $(CFLAGS) $(CPPFLAGS)

.S.o:
	$(CC) -MD -c $< -o $@ $(CFLAGS) $(CPPFLAGS)

clean:
	rm -f adhDOS.kernel
	rm -f $(OBJS) *.o */*.o */*/*.o */*/*/*.o
	rm -f $(OBJS:.o=.d) *.d */*.d */*/*.d */*/*/*.d
	rm -f $(ARCHDIR)/asm_offsets.h $(ARCHDIR)/gen_offsets

install: install-headers install-kernel

install-headers:
	mkdir -p $(DESTDIR)$(INCLUDEDIR)
	cp -R --preserve=timestamps include/. $(DESTDIR)$(INCLUDEDIR)/.

install-kernel: adhDOS.kernel
	mkdir -p $(DESTDIR)$(BOOTDIR)
	cp adhDOS.kernel $(DESTDIR)$(BOOTDIR)

-include $(OBJS:.o=.d)
