# MIPS linux kernel challenge

```
user: ctf
password: asisctf
```

* Kernel Space Arbitrary read/write
* I found I can overwrite module code text
* commit_creds(prepare_kernel_cred(0))
* Get root privileges


