all: kernel_space.o

kernel_space.o: kernel_space.c shared_defs.h
clang -O2 -g -target bpf -Wall -c kernel_space.c -o kernel_space.o

clean:
rm -f kernel_space.o
