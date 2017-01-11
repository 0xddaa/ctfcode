section .text
global _start
_start:
    jmp path
qq:
    xor rax, rax
    mov rdi, [rsp]
    push rax
    push rdi
    mov rsi, rsp
    mov rdx, rax
    mov al, 59
	syscall

path:
    call qq
    db "/bin/sh", 0
