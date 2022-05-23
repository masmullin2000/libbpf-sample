APP=exec

# NOTE: Mainline (5.18) and bpf-next version of bpftool has a segfault
#       when generating exec.skel.h
#

# this is for using distribution provided bpftool
BPFTOOL=bpftool

# Change these to wherever you keep
# your mainline and stable kernel
LINUX_KERNEL_DIR_MAINLINE=/code/mainline
LINUX_KERNEL_DIR_STABLE=/code/linux-stable
LINUX_KERNEL_DIR_BPF_NEXT=/code/bpf-next

# change this to set whether you want to use
# mainline or stable
#LINUX_KERNEL_DIR=$(LINUX_KERNEL_DIR_MAINLINE)
#LINUX_KERNEL_DIR=$(LINUX_KERNEL_DIR_STABLE)
LINUX_KERNEL_DIR=$(LINUX_KERNEL_DIR_BPF_NEXT)
#BPFTOOL=$(LINUX_KERNEL_DIR)/tools/bpf/bpftool/bpftool

.PHONY: $(APP)
$(APP): skel
	clang exec.c -lbpf -lelf -o $(APP)

.PHONY: vmlinux
vmlinux:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

.PHONY: bpf
bpf: vmlinux
	clang -g -O3 -target bpf -D__TARGET_ARCH_x86_64 -c exec.bpf.c -o exec.bpf.o

.PHONY: skel
skel: bpf
	$(BPFTOOL) gen skeleton exec.bpf.o name exec > exec.skel.h

.PHONY: run
run: $(APP)
	sudo ./$(APP)

.PHONY: clean
clean:
	-rm -rf *.o *.skel.h vmlinux.h $(APP)

.PHONY: gdb
gdb: bpf
	sudo gdb --args $(BPFTOOL) gen skeleton exec.bpf.o name exec
