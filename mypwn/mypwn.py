import telnetlib
import socket

host = ""
port = -1

t = telnetlib.Telnet(host, port)
s = t.get_socket()

#*************************************#
# handle connection, input and output #
#*************************************#

def connect(host, port):
    global t, s
    t = telnetlib.Telnet(host, port)
    s = t.get_socket()

def read_until(end)
    buf = ""
    while True:
        buf += s.recv(1)
        if end in buf:
            break

    return buf

def read_line():
    return read_until("\n")

def send(buf):
    s.send(buf)

def send_line(buf):
    send(buf+"\n")

#******************************#
#     convert value format     #
#******************************#
def pack(addr):
    assert len(addr) == 4, "length of address error!"
    return addr[::-1].encode("hex")

def unpack(addr):
    return addr.decode("hex")[::-1]

def get_libcfunc(remote_addr, src_offset, dest_offset):
    libc_base = int(remote_addr, 16) - src_offset
    return hex(libc_base + dest_offset)[2:]

def int_to_dword(num):
    if num > 0:
        return hex(num)
    else:
        return hex(pow(2, 32) + num)
