# Ranger Login

<figure><img src="../../../.gitbook/assets/unknown (9).png" alt=""><figcaption></figcaption></figure>

given a zip file that contains:

<figure><img src="../../../.gitbook/assets/unknown (10).png" alt=""><figcaption></figcaption></figure>

first, we see inside index.html and we see a wasm call module named **check\_flag**:

<figure><img src="../../../.gitbook/assets/unknown (11).png" alt=""><figcaption></figcaption></figure>

In short, the HTML will call a WASM function named **check\_flag** with two arguments: username and password. if it returns 1 (true), then it prints the flag.

now we see the **check\_flag** function in challenge.js:

<figure><img src="../../../.gitbook/assets/unknown (12).png" alt=""><figcaption></figcaption></figure>

cause the grep result is a bit unclear, so in short:

**check\_flag** is exported as a "c" function from WASM. So we have to reverse the WASM. first we convert the WASM to WAT (WebAssembly Text Format).

<figure><img src="../../../.gitbook/assets/unknown (13).png" alt=""><figcaption></figcaption></figure>

from the WAT we get:

<figure><img src="../../../.gitbook/assets/unknown (14).png" alt=""><figcaption></figcaption></figure>

and in the body function, there's a recurring pattern:

* i32.load8\_u -> takes one byte from the argument
* i32.const \<number> -> literal byte
* i32.ne -> check if the same
* br\_if -> exit if wrong

from there, we get 2 hex string, username and password, each with 32 characters:

username: 888765cc1062ceef99457cef217d25c9

password: b54e4863ef82db84ada3143fff3d1fc2

then we just open the index.html and put it in solver.js:

```javascript
const Module = require('./challenge.js');

Module.print = (...a) => console.log(...a);
Module.printErr = (...a) => console.error(...a);
Module.noExitRuntime = true;

Module.onRuntimeInitialized = () => {
  const u = '888765cc1062ceef99457cef217d25c9';
  const p = 'b54e4863ef82db84ada3143fff3d1fc2';
  const ok = Module.ccall('check_flag', 'number', ['string', 'string'], [u, p]);
  console.log(ok ? `RTRTNI25{${u}${p}}` : 'nope');
};
```

if we run it:

<figure><img src="../../../.gitbook/assets/unknown (15).png" alt=""><figcaption></figcaption></figure>

#### Flag: RTRTNI25{888765cc1062ceef99457cef217d25c9b54e4863ef82db84ada3143fff3d1fc2}
