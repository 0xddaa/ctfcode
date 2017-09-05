#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

def calc_k(idx):
    k = c[idx + 1] - m[idx] - c[idx]
    while k < 0:
        k += 128
    return k

def calc_m(idx):
    m = c[idx + 1] - k[idx % 13] - c[idx]
    while m < 0:
        m += 128
    return m

c = [ ord(c) for c in '7c153a474b6a2d3f7d3f7328703e6c2d243a083e2e773c45547748667c1511333f4f745e'.decode('hex')]

k = [0 for i in range(13)]
k[8] = 121
k[4] = 89

m = [0 for i in range(21)] + [ord('|')] + k

k_idx = 4

while 0 in k:
    m_idx = 21 + k_idx + 1
    m[m_idx] = k[k_idx]
    k_idx = m_idx % 13
    k[k_idx] = calc_k(m_idx)

log.info('key: ' + ''.join(chr(i) for i in k))

for i in range(21):
    m[i] = calc_m(i)

log.info('flag: ' + ''.join(chr(i) for i in m))
