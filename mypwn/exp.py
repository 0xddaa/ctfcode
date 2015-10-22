#!/usr/bin/python

from pwn import *
info = log.info

# setting 
elf = ELF("")

def local():
	global libc, r
	libc = ELF("local")
	r = remote("localhost", 5566)

def fuck():
	global libc, r
	libc = ELF("libc.so.6")
	r = remote("52.68.53.28", 56746)

local()
#fuck()

r.interactive()

