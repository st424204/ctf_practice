from pwn import *
import numpy as np
re1 = ELF("./re1")

count = 0

A = ""
col = []
for i in range(7):
	for j in range(9):
		for k in range(3):
			for l in range(5):
				for m in range(2):
					for n in range(4):
						row = []
						for ii in range(20):
							addr = 80 * m + 0x5460 * i + 0x960 * j + 20 * n + 0xA0 * l + 0x320 * k + ii
							row += [ u32(re1.read(0x48d010+addr*4,4)) ]
						addr = 4 * (2 * (15 * j + 0x87 * i + 5 * k + l) + m) + n
						#addr = count*4
						col += [ u32(re1.read(0x520A90+addr*4,4)) ]
						if count == 0:
							A = np.array(row)
						else:
							A = np.vstack([A,row])
						count+=1
						if count == 20:
							#print A
							B = np.array(col)
							#print B
							x = np.linalg.solve(A, B)
							y = x.tolist()
							#print y
							flag = ""
							for yy in y:
								flag+=chr(int(round(yy)))
							print flag
							open("flag","w").write(flag)
							exit(0)

#u32(re1.read(0x48d010,4))

