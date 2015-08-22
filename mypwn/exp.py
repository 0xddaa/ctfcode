#!/usr/bin/python

from pwn import *
from pwnlib.log import *


# setting 
elf = ELF("bamboobox")
libc = ELF("libc.so.6")

# trigger vuln
r = remote("localhost", 5566)

r.interactive()

