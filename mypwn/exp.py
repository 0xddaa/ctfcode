#!/usr/bin/python

from pwn import *
from pwnlib.log import *

def pad(size, buf=''):
    chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    buflen = size - len(buf)
    assert buflen >= 0, "%d bytes over" % (-buflen,)
    return ''.join(random.choice(chars) for i in xrange(buflen))

# setting 
elf = ELF("bamboobox")
libc = ELF("libc.so.6")

# trigger vuln
r = remote("localhost", 5566)

r.interactive()

