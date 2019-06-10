# Solve it after Finals


## Hint
```
Race with mmap and munmap to get out-of-bounds to leak kernel address. The idea comes from CVE-2015-1805
CVE-2019-9213 puts gadget to address 0
NULL pointer dereference to control rip
```

Use `userfaultfd` to 100% out-of-bounds leak kernel address



