SHELL=/bin/bash -o pipefail
DEST_DIR?=/src/dist

build:
	@mkdir -p "$(DEST_DIR)"
	@clang -D__KERNEL__ -D__ASM_SYSREG_H \
		-Wno-unused-value \
		-Wno-compare-distinct-pointer-types \
		-Wunused \
		-Wall \
		-Werror \
		-fno-stack-protector \
		-O2 -emit-llvm -c metrics.c \
		-o - | llc9 -march=bpf -filetype=obj -o "${DEST_DIR}/metrics.o"