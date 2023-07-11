all: /app/a.out /app/bpf.elf
/app:
	mkdir -p /app
/app/a.out: src/main.c /app
	clang -Wall -Wextra -O2 -g src/main.c -lbpf -o /app/a.out

/app/bpf.elf:  src/parser.c /app
	clang -Wall -Wextra -O2 -emit-llvm -g -c \
		src/parser.c \
		-S -o - \
		| llc -march=bpf -filetype=obj -o /app/bpf.elf
