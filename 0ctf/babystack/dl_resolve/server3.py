from pwn import *


l = listen(port=1330)

r = l.wait_for_connection()

r.interactive()
