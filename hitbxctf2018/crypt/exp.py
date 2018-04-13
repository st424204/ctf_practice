from pwn import *




def orz(ciper,val):
	ciper = int(ciper,16)
	ciper ^= val
	ciper = ("%x"%(ciper)).rjust(32,"0")
	return ciper







#r = process(["python3","cbc.py"])
r = remote("47.90.125.237", 9999)

r.sendlineafter(">>","r")
r.sendlineafter(">>","admin".ljust(0x10,"a")+"a"*0x10)

r.recvline()

cookie = r.recvline()[:-1]
v1 = cookie[:5*32]+orz(cookie[5*32:6*32],ord('\x0c')^ord('\x2b'))+cookie[6*32:]


r.sendlineafter(">>","c")
r.sendlineafter(">>","admin")
mac = r.recvline()[:-1]

part3 = int("10"*0x10,16)^int(mac[34:]+"01",16)

v2 = v1[:2*32]+orz(cookie[2*32:3*32],part3)+ v1[3*32:]

print v2


r.sendlineafter(">>","l")
r.sendlineafter(">>",v2)

r.recvuntil("', '")
plain = r.recvuntil("'")[:-1]

part2 = int(mac[2:34],16)^ int(plain[2:34],16)

v3 = v2[:32]+orz(v2[32:64],part2)+v2[64:]


r.sendlineafter(">>","l")
r.sendlineafter(">>",v3)

r.recvuntil("', '")
plain = r.recvuntil("'")[:-1]


part1 = int(mac[:2],16)^ int(plain[:2],16)

v4 = orz(v3[:32],part1)+v3[32:]


print v4






r.interactive()
