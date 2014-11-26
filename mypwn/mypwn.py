import telnetlib
import socket

#host = "localhost"
#port = 55666

#t = telnetlib.Telnet(host, port)
#s = t.get_socket()
t = None
s = None

#*************************************#
# handle connection, input and output #
#*************************************#

def get_t():
    return t

def get_s():
    return s

def connect(host, port):
    global t, s
    t = telnetlib.Telnet(host, port)
    s = t.get_socket()

def read_until(end):
    global s
    buf = ""
    while True:
        buf += s.recv(1)
        if end in buf:
            break

    return buf

def read_line():
    return read_until("\n")

"""
If daemon use read() to get input, using send(buf, length) to prevent I/O sequence confusion.
"""
def send(buf, length = 0):
    global s

    for i in range(length - len(buf)):
        buf += "\x00"
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
    assert len(addr) == 8, "length of address error!"
    return addr.decode("hex")[::-1]

def int_to_dword(num):
    if num > 0:
        dword = hex(num)[2:]
    else:
        dword = hex(pow(2, 32) + num)[2:]
    
    for i in range(8 - len(dword)):
        dword = "0" + dword

    return dword

"""
Get base address after we got memory address.
ex: get buf addr, return eip
"""
def get_base(addr, offset):
    return int_to_dword(int(addr, 16) - offset)

"""
Get real address after we got memory bass
"""
def get_addr(base, offset):
    return int_to_dword(int(base, 16) + offset)

#*************************#
#     count libc base     #
#*************************#

class Libc:
    path = ""
    libc_base = -1
    func = {"write" :"__write",\
            "read" : "__read",\
            "system" : "__libc_system",\
            "open" : "__open",\
            "gets" : "_IO_gets"}

    def __init__(self, path):
        self.path = path
    
    def get_base(self, f, addr):
        assert self.path != "", "plz set libc path first!"
        import subprocess
        cmd = "readelf -s " + self.path + "| grep " + self.func[f] + "@@" + " | awk '{print $2}'"
        p = subprocess.Popen(cmd, shell = True, stdout = subprocess.PIPE)
        offset = int(p.stdout.read().strip(), 16)
        self.libc_base = int(addr, 16) - offset
        print "libc_base : " + hex(self.libc_base)

    def libc(self, f):
        assert self.libc_base != -1, "plz count libc base first!"
        import subprocess
        cmd = "readelf -s " + self.path + "| grep " + self.func[f] + "@@" + " | awk '{print $2}'"
        p = subprocess.Popen(cmd, shell = True, stdout = subprocess.PIPE)
        offset = int(p.stdout.read().strip(), 16)
        addr = hex(self.libc_base + offset)
        print f + " : " + addr 
        return addr[2:]

       
