SHELL=/bin/bash -o pipefail
SRC_DIR?=/bpf/src
DEST_DIR?=/bpf/dist

LINUX_HEADERS ?= /usr/src/linux-headers-5.10.38-0-lts

build:
	@mkdir -p "$(DEST_DIR)"
	@clang -D__KERNEL__ -D__ASM_SYSREG_H \
		-Wno-unused-value \
		-Wno-compare-distinct-pointer-types \
		-Wunused \
		-Wall \
		-Werror \
		-fno-stack-protector \
		-I$(LINUX_HEADERS)/arch/x86/include \
		-I$(LINUX_HEADERS)/arch/x86/include/generated \
		-I$(LINUX_HEADERS)/arch/x86/include/generated/uapi \
		-I$(LINUX_HEADERS)/arch/x86/include/uapi \
		-I$(LINUX_HEADERS)/include/uapi \
		-I$(LINUX_HEADERS)/include/generated/uapi \
		-I$(LINUX_HEADERS)/include \
		-O2 -emit-llvm -g -c ${SRC_DIR}/metrics_sock.c \
		-o - | llc -march=bpf -filetype=obj -o "${DEST_DIR}/metrics_sock.o"
.PHONY: build

dump: build
	@llvm-objdump -S -no-show-raw-insn "${DEST_DIR}/metrics_sock.o" > "${DEST_DIR}/metrics_sock.s"
.PHONY: dump
