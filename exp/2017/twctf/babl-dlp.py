#!/usr/bin/env python
from pwn import *
from rsa.transform import *

HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 1234)

p = 160634950613302858781995506902938412625377360249559915379491492274326359260806831823821711441204122060415286351711411013883400510041411782176467940678464161205204391247137689678794367049197824119717278923753940984084059450704378828123780678883777306239500480793044460796256306557893061457956479624163771194201

r = remote(HOST, PORT)

r.sendline(hex(0))
last = int(r.recvline().strip('\nL'), 16)

flag = 0
bits = ''

msg = log.progress('flag')
while 'TWCTF' not in int2bytes(flag):
    msg.status(int2bytes(flag))
    tmp = len(bits)

    r.sendline(hex((1 << tmp) + flag))
    b = int(r.recvline().strip('\nL'), 16)

    if last * pow(2, pow(2, tmp), p) % p == b:
        bits = '0' + bits
    elif b * pow(2, pow(2, tmp), p) % p == last:
        bits = '1' + bits
        last = b
    else:
        raise AssertionError

    flag = int(bits, 2)

msg.success(int2bytes(flag))
