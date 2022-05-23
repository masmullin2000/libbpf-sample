APP=exec

# NOTE: Current shipping stable kernel bpftool has a bug
#       where the rodata is not correctly attributed to
#       the exec.maps struct upon the generation of exec.skel.h
#
#       Mainline (5.18) and bpf-next version of bpftool has a segfault
#       when generating exec.skel.h
#

# this is for using distribution provided bpftool
BPFTOOL=bpftool

# Change these to wherever you keep
# your mainline and stable kernel
LINUX_KERNEL_DIR_MAINLINE=/code/mainline
LINUX_KERNEL_DIR_STABLE=/code/linux-stable

# change this to set whether you want to use
# mainline or stable
#LINUX_KERNEL_DIR=$(LINUX_KERNEL_DIR_MAINLINE)
LINUX_KERNEL_DIR=$(LINUX_KERNEL_DIR_STABLE)
#BPFTOOL=$(LINUX_KERNEL_DIR)/tools/bpf/bpftool/bpftool

.PHONY: $(APP)
$(APP): skel
	# Fixup
	sed -i "s/obj->rodata/obj->maps.rodata/g" exec.skel.h
	sed -i "s/obj->data/obj->maps.data/g" exec.skel.h
	clang exec.c -lbpf -lelf -o $(APP)

.PHONY: vmlinux
vmlinux:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

.PHONY: bpf
bpf: vmlinux
	clang -O3 -target bpf -D__TARGET_ARCH_x86_64 -c exec.bpf.c -o exec.bpf.o

.PHONY: skel
skel: bpf
	$(BPFTOOL) gen skeleton exec.bpf.o name exec > exec.skel.h

.PHONY: run
run: $(APP)
	sudo ./$(APP)

.PHONY: clean
clean:
	-rm -rf *.o *.skel.h vmlinux.h $(APP)
