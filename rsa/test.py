#!/usr/bin/python

import hashlib
import sys
from Crypto.PublicKey import RSA

def egcd(a, b):
	if a == 0:
		return (b, 0, 1)
	else:
		g, y, x = egcd(b % a, a)
		return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m


pubkey = """-----BEGIN PUBLIC KEY-----
MCwwDQYJKoZIhvcNAQEBBQADGwAwGAIRALSMJB2tLS9JUsjztc0Q1vkCAwEAAQ==
-----END PUBLIC KEY-----
"""

pubrsa = RSA.importKey(pubkey)
n = pubrsa.n
e = pubrsa.e
p = 15448096144646045267
q = 15535163108278055939
r = (p-1)*(q-1)
d = modinv(e, r)

priv = RSA.construct([long(n), long(e), long(d)])
pub = RSA.construct([long(n), long(e)])
cipher = pub.encrypt("123", pub)[0]
print cipher
plain = priv.decrypt(cipher)
print plain
