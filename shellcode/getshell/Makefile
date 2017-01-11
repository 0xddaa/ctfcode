NAME=$(shell basename $(shell pwd))

all: 32 64

b32:
	nasm -f elf32 $(NAME).asm -o asm.o && ld asm.o -m elf_i386 -o elf
	objcopy -O binary asm.o asm.bin

b64:
	nasm -f elf64 $(NAME)64.asm -o asm.o && ld asm.o -m elf_x86_64 -o elf64
	objcopy -O binary asm.o asm.bin

32: b32
	@echo len: $(firstword $(subst ' ', ,$(shell wc -c asm.bin)))
	@xxd -p -c 256 asm.bin

64: b64
	@echo len: $(firstword $(subst ' ', ,$(shell wc -c asm.bin)))
	@xxd -p -c 256 asm.bin

clean:
	rm -f asm.o asm.bin
