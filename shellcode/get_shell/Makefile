all:
	nasm -f elf32 getflag.asm -o asm.o && ld asm.o -m elf_i386 -o elf
64:
	nasm -f elf64 getflag64.asm -o asm.o && ld asm.o -m elf_x86_64 -o elf64
