SHELL=/bin/bash -o pipefail
DEST_DIR?=/src/dist

LINUX_HEADERS ?= /usr/src/linux-headers-5.10.26-0-lts

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
		-O2 -emit-llvm -g -c metrics.c \
		-o - | llc -march=bpf -filetype=obj -o "${DEST_DIR}/metrics.o"
.PHONY: build

dump: build
	@llvm-objdump -S -no-show-raw-insn "${DEST_DIR}/metrics.o" > "${DEST_DIR}/metrics.s"
.PHONY: dump
