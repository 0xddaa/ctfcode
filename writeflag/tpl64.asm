section .text
global _start
_start:
    jmp path
open:
; open(path, 0 , 0)
    xor rax, rax
    mov rdi, [rsp]
    mov si, 0x241
    mov dx, 0x1a0
    mov al, 0x2
    syscall
    mov rbx, rax
    jmp flag
copy:
    mov rsi, [rsp]
    mov rdi, rsp 
    xor rcx, rcx
loop:
    mov al, [rsi + rcx]
    mov [rdi + rcx], al
    inc rcx
    cmp rcx, %s
    jne loop
    xor rdx, rdx
    mov [rdi + rcx], dl 
write:
; write(fd, esp, 32)
    push rsp
    mov rsi, [rsp]
    mov rdi, rbx
    mov %s, %s
    mov al, 0x1
    syscall
end:
    xor rdi, rdi
    xor rax, rax
    mov al, 0x3c
    syscall

flag:
    call copy
    db "%s"

path:
    call open
    db "%s", 0

nop:
    nop
    nop
    nop
    nop
