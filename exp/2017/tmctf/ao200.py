#!/usr/bin/env python
# -*- coding: utf-8 -*-

def is_prime(n):
    i = 2
    while i < n:
        if n % i == 0:
            return False
        i += 1
    return True

def odd_sum(n):
    i = 1
    while True:
        n -= i
        if n == 0:
            return True
        elif n < 0:
            return False
        i += 2

def flag_sum(code):
    s = 0
    for d in str(code):
        s += ord(d)
    return s

with open('primes', 'r') as f:
    tmp = f.read()
primes = [int(p) for p in tmp.split(',')]

a = []
for p in primes:
    x1 = p / 10000 % 100
    x2 = p / 100 % 100
    x3 = p % 100

    if not is_prime(x1):
        continue

    if not is_prime(x2):
        continue

    if not odd_sum(x3):
        continue

    if (x3 * x3 ^ (p / 100 % 10000)) >> 8 != 0:
        continue

    if not is_prime(flag_sum(p) - 288):
        continue

    a.append(p)

with open('xd', 'w') as f:
    for p in a:
        f.write(str(p) + '\n')
