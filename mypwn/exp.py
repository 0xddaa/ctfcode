#!/usr/bin/python

from pwn import *
info = log.info

# setting 
elf = ELF("")
libc = ELF("libc.so.6")

# trigger vuln
r = remote("localhost", 5566)

r.interactive()

