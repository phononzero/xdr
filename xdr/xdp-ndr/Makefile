CLANG ?= clang
BPFTOOL ?= bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
              -I/usr/include -I/usr/include/bpf

VMLINUX_H := vmlinux.h

.PHONY: all clean vmlinux

all: $(VMLINUX_H) ndr.bpf.o

$(VMLINUX_H):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

ndr.bpf.o: ndr.bpf.c $(VMLINUX_H)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -f *.o $(VMLINUX_H)
