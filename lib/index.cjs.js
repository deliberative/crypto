'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

// Copyright (C) 2022 Deliberative Technologies P.C.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
/**
 * Webassembly Memory is separated into 64kb contiguous memory "pages".
 * This function takes memory length in bytes and converts it to pages.
 */
const memoryLenToPages = (memoryLen, minPages, maxPages) => {
    minPages = minPages || 32; // 2mb // 256; // 16mb // 6; // 384kb
    maxPages = maxPages || 1600; // 100mb for argon2 // 256; // 16mb // 8; // 512kb
    const pageSize = 64 * 1024;
    const ceil = Math.ceil(memoryLen / pageSize);
    if (ceil > maxPages)
        throw new Error(`Memory required is ${ceil * pageSize} bytes while declared maximum is ${maxPages * pageSize} bytes`);
    return ceil < minPages ? minPages : ceil;
};

// Copyright (C) 2022 Deliberative Technologies P.C.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
const crypto_hash_sha512_BYTES = 64;
const crypto_box_poly1305_AUTHTAGBYTES = 16;
const crypto_box_x25519_PUBLICKEYBYTES = 32;
const crypto_box_x25519_SECRETKEYBYTES = 32;
const crypto_box_x25519_NONCEBYTES = 12;
const crypto_sign_ed25519_BYTES = 64;
const crypto_sign_ed25519_SEEDBYTES = 32;
const crypto_sign_ed25519_PUBLICKEYBYTES = 32;
const crypto_sign_ed25519_SECRETKEYBYTES = 64;
const crypto_pwhash_argon2id_SALTBYTES = 16;

// Copyright (C) 2022 Deliberative Technologies P.C.
const newKeyPairMemory = () => {
    const memoryLen = (crypto_sign_ed25519_PUBLICKEYBYTES + crypto_sign_ed25519_SECRETKEYBYTES) *
        Uint8Array.BYTES_PER_ELEMENT;
    const pages = memoryLenToPages(memoryLen);
    return new WebAssembly.Memory({ initial: pages, maximum: pages });
};
const keyPairFromSeedMemory = () => {
    const memoryLen = (crypto_sign_ed25519_PUBLICKEYBYTES +
        crypto_sign_ed25519_SECRETKEYBYTES +
        crypto_sign_ed25519_SEEDBYTES) *
        Uint8Array.BYTES_PER_ELEMENT;
    const pages = memoryLenToPages(memoryLen);
    return new WebAssembly.Memory({ initial: pages, maximum: pages });
};
const keyPairFromSecretKeyMemory = () => {
    const memoryLen = (crypto_sign_ed25519_PUBLICKEYBYTES + crypto_sign_ed25519_SECRETKEYBYTES) *
        Uint8Array.BYTES_PER_ELEMENT;
    const pages = memoryLenToPages(memoryLen);
    return new WebAssembly.Memory({ initial: pages, maximum: pages });
};
const signMemory = (messageLen) => {
    const memoryLen = (messageLen +
        crypto_sign_ed25519_BYTES +
        crypto_sign_ed25519_SECRETKEYBYTES +
        crypto_hash_sha512_BYTES) *
        Uint8Array.BYTES_PER_ELEMENT;
    const pages = memoryLenToPages(memoryLen);
    return new WebAssembly.Memory({ initial: pages, maximum: pages });
};
const verifyMemory = (messageLen) => {
    const memoryLen = (messageLen +
        crypto_sign_ed25519_BYTES +
        crypto_sign_ed25519_PUBLICKEYBYTES) *
        Uint8Array.BYTES_PER_ELEMENT;
    const pages = memoryLenToPages(memoryLen);
    return new WebAssembly.Memory({ initial: pages, maximum: pages });
};
const encryptMemory = (messageLen, additionalDataLen) => {
    const sealedBoxLen = crypto_box_x25519_PUBLICKEYBYTES + // ephemeral x25519 public key
        crypto_box_x25519_NONCEBYTES + // xchacha uses 24 byte nonce while ietf 12
        messageLen +
        crypto_box_poly1305_AUTHTAGBYTES; // 16 bytes poly1305 auth tag
    const memoryLen = (messageLen +
        crypto_sign_ed25519_PUBLICKEYBYTES +
        additionalDataLen +
        sealedBoxLen +
        1 * (messageLen + crypto_box_poly1305_AUTHTAGBYTES) + // malloc'd
        2 * crypto_box_x25519_PUBLICKEYBYTES + // malloc'd
        2 * crypto_box_x25519_SECRETKEYBYTES + // malloc'd
        crypto_box_x25519_NONCEBYTES) * // malloc'd
        Uint8Array.BYTES_PER_ELEMENT;
    const pages = memoryLenToPages(memoryLen);
    return new WebAssembly.Memory({ initial: pages, maximum: pages });
};
const decryptMemory = (encryptedLen, additionalDataLen) => {
    const decryptedLen = encryptedLen -
        crypto_box_x25519_PUBLICKEYBYTES - // x25519 ephemeral
        crypto_box_x25519_NONCEBYTES - // nonce
        crypto_box_poly1305_AUTHTAGBYTES; // authTag
    const memoryLen = (encryptedLen +
        crypto_sign_ed25519_SECRETKEYBYTES +
        additionalDataLen +
        decryptedLen +
        2 * crypto_box_x25519_PUBLICKEYBYTES + // malloc'd
        crypto_box_x25519_NONCEBYTES + // malloc'd
        crypto_box_x25519_SECRETKEYBYTES) * // malloc'd
        Uint8Array.BYTES_PER_ELEMENT;
    const pages = memoryLenToPages(memoryLen);
    return new WebAssembly.Memory({ initial: pages, maximum: pages });
};
var memory$3 = {
    newKeyPairMemory,
    keyPairFromSeedMemory,
    keyPairFromSecretKeyMemory,
    signMemory,
    verifyMemory,
    encryptMemory,
    decryptMemory,
};

var libsodiumMethodsModule = (() => {
  var _scriptDir = typeof document !== 'undefined' && document.currentScript ? document.currentScript.src : undefined;
  if (typeof __filename !== 'undefined') _scriptDir = _scriptDir || __filename;
  return (
function(libsodiumMethodsModule) {
  libsodiumMethodsModule = libsodiumMethodsModule || {};
var f;f||(f=typeof libsodiumMethodsModule !== 'undefined' ? libsodiumMethodsModule : {});var aa,ba;f.ready=new Promise(function(a,b){aa=a;ba=b;});var ca=Object.assign({},f),da=[],ea="./this.program",k=(a,b)=>{throw b;},fa="object"==typeof window,l="function"==typeof importScripts,t="object"==typeof process&&"object"==typeof process.versions&&"string"==typeof process.versions.node,u="",ha,v,w,fs,x,ia;
if(t)u=l?require("path").dirname(u)+"/":__dirname+"/",ia=()=>{x||(fs=require("fs"),x=require("path"));},ha=function(a,b){ia();a=x.normalize(a);return fs.readFileSync(a,b?void 0:"utf8")},w=a=>{a=ha(a,!0);a.buffer||(a=new Uint8Array(a));return a},v=(a,b,c)=>{ia();a=x.normalize(a);fs.readFile(a,function(d,e){d?c(d):b(e.buffer);});},1<process.argv.length&&(ea=process.argv[1].replace(/\\/g,"/")),da=process.argv.slice(2),k=(a,b)=>{if(noExitRuntime)throw process.exitCode=a,b;b instanceof ja||y("exiting due to exception: "+
b);process.exit(a);},f.inspect=function(){return "[Emscripten Module object]"};else if(fa||l)l?u=self.location.href:"undefined"!=typeof document&&document.currentScript&&(u=document.currentScript.src),_scriptDir&&(u=_scriptDir),0!==u.indexOf("blob:")?u=u.substr(0,u.replace(/[?#].*/,"").lastIndexOf("/")+1):u="",ha=a=>{var b=new XMLHttpRequest;b.open("GET",a,!1);b.send(null);return b.responseText},l&&(w=a=>{var b=new XMLHttpRequest;b.open("GET",a,!1);b.responseType="arraybuffer";b.send(null);return new Uint8Array(b.response)}),
v=(a,b,c)=>{var d=new XMLHttpRequest;d.open("GET",a,!0);d.responseType="arraybuffer";d.onload=()=>{200==d.status||0==d.status&&d.response?b(d.response):c();};d.onerror=c;d.send(null);};var ka=f.print||console.log.bind(console),y=f.printErr||console.warn.bind(console);Object.assign(f,ca);ca=null;f.arguments&&(da=f.arguments);f.thisProgram&&(ea=f.thisProgram);f.quit&&(k=f.quit);var z=f.dynamicLibraries||[],A;f.wasmBinary&&(A=f.wasmBinary);var noExitRuntime=f.noExitRuntime||!0;
"object"!=typeof WebAssembly&&B("no native wasm support detected");var C,la=!1,ma="undefined"!=typeof TextDecoder?new TextDecoder("utf8"):void 0;
function D(a,b,c){var d=b+c;for(c=b;a[c]&&!(c>=d);)++c;if(16<c-b&&a.buffer&&ma)return ma.decode(a.subarray(b,c));for(d="";b<c;){var e=a[b++];if(e&128){var g=a[b++]&63;if(192==(e&224))d+=String.fromCharCode((e&31)<<6|g);else {var h=a[b++]&63;e=224==(e&240)?(e&15)<<12|g<<6|h:(e&7)<<18|g<<12|h<<6|a[b++]&63;65536>e?d+=String.fromCharCode(e):(e-=65536,d+=String.fromCharCode(55296|e>>10,56320|e&1023));}}else d+=String.fromCharCode(e);}return d}
function na(a,b,c,d){if(!(0<d))return 0;var e=c;d=c+d-1;for(var g=0;g<a.length;++g){var h=a.charCodeAt(g);if(55296<=h&&57343>=h){var m=a.charCodeAt(++g);h=65536+((h&1023)<<10)|m&1023;}if(127>=h){if(c>=d)break;b[c++]=h;}else {if(2047>=h){if(c+1>=d)break;b[c++]=192|h>>6;}else {if(65535>=h){if(c+2>=d)break;b[c++]=224|h>>12;}else {if(c+3>=d)break;b[c++]=240|h>>18;b[c++]=128|h>>12&63;}b[c++]=128|h>>6&63;}b[c++]=128|h&63;}}b[c]=0;return c-e}
function oa(a){for(var b=0,c=0;c<a.length;++c){var d=a.charCodeAt(c);127>=d?b++:2047>=d?b+=2:55296<=d&&57343>=d?(b+=4,++c):b+=3;}return b}var E,G,H,I,pa;function qa(a){E=a;f.HEAP8=G=new Int8Array(a);f.HEAP16=new Int16Array(a);f.HEAP32=I=new Int32Array(a);f.HEAPU8=H=new Uint8Array(a);f.HEAPU16=new Uint16Array(a);f.HEAPU32=new Uint32Array(a);f.HEAPF32=new Float32Array(a);f.HEAPF64=pa=new Float64Array(a);}var ra=f.INITIAL_MEMORY||2097152;
f.wasmMemory?C=f.wasmMemory:C=new WebAssembly.Memory({initial:ra/65536,maximum:1600});C&&(E=C.buffer);ra=E.byteLength;qa(E);var J=new WebAssembly.Table({initial:16,element:"anyfunc"}),sa=[],ta=[],ua=[],va=[],xa=[],K=!1;function ya(){var a=f.preRun.shift();sa.unshift(a);}var L=0,M=null;function Aa(){L++;f.monitorRunDependencies&&f.monitorRunDependencies(L);}
function Ba(){L--;f.monitorRunDependencies&&f.monitorRunDependencies(L);if(0==L&&(M)){var a=M;M=null;a();}}function B(a){if(f.onAbort)f.onAbort(a);a="Aborted("+a+")";y(a);la=!0;a=new WebAssembly.RuntimeError(a+". Build with -sASSERTIONS for more info.");ba(a);throw a;}function Ca(){return N.startsWith("data:application/octet-stream;base64,")}var N;N="libsodiumMethodsModule.wasm";if(!Ca()){var Da=N;N=f.locateFile?f.locateFile(Da,u):u+Da;}
function Ea(){var a=N;try{if(a==N&&A)return new Uint8Array(A);if(w)return w(a);throw "both async and sync fetching of the wasm failed";}catch(b){B(b);}}
function Fa(){if(!A&&(fa||l)){if("function"==typeof fetch&&!N.startsWith("file://"))return fetch(N,{credentials:"same-origin"}).then(function(a){if(!a.ok)throw "failed to load wasm binary file at '"+N+"'";return a.arrayBuffer()}).catch(function(){return Ea()});if(v)return new Promise(function(a,b){v(N,function(c){a(new Uint8Array(c));},b);})}return Promise.resolve().then(function(){return Ea()})}
var Ga={33664:()=>f.K(),33700:()=>{if(void 0===f.K)try{var a="object"===typeof window?window:self,b="undefined"!==typeof a.crypto?a.crypto:a.msCrypto;a=function(){var d=new Uint32Array(1);b.getRandomValues(d);return d[0]>>>0};a();f.K=a;}catch(d){try{var c=require("crypto");a=function(){var e=c.randomBytes(4);return (e[0]<<24|e[1]<<16|e[2]<<8|e[3])>>>0};a();f.K=a;}catch(e){throw "No secure random number generator found";}}}};
function ja(a){this.name="ExitStatus";this.message="Program terminated with exit("+a+")";this.status=a;}var O={},Ha=new Set([]),Ia={get:function(a,b){(a=O[b])||(a=O[b]=new WebAssembly.Global({value:"i32",mutable:!0}));Ha.has(b)||(a.required=!0);return a}};function P(a){for(;0<a.length;)a.shift()(f);}
function Ja(a){function b(){for(var n=0,r=1;;){var F=a[e++];n+=(F&127)*r;r*=128;if(!(F&128))break}return n}function c(){var n=b();e+=n;return D(a,e-n,n)}function d(n,r){if(n)throw Error(r);}var e=0,g=0,h="dylink.0";a instanceof WebAssembly.Module?(g=WebAssembly.Module.customSections(a,h),0===g.length&&(h="dylink",g=WebAssembly.Module.customSections(a,h)),d(0===g.length,"need dylink section"),a=new Uint8Array(g[0]),g=a.length):(g=1836278016==(new Uint32Array((new Uint8Array(a.subarray(0,24))).buffer))[0],
d(!g,"need to see wasm magic number"),d(0!==a[8],"need the dylink section to be first"),e=9,g=b(),g=e+g,h=c());var m={B:[],ia:new Set,aa:new Set};if("dylink"==h){m.L=b();m.X=b();m.J=b();m.ha=b();h=b();for(var p=0;p<h;++p){var q=c();m.B.push(q);}}else for(d("dylink.0"!==h);e<g;)if(h=a[e++],p=b(),1===h)m.L=b(),m.X=b(),m.J=b(),m.ha=b();else if(2===h)for(h=b(),p=0;p<h;++p)q=c(),m.B.push(q);else if(3===h)for(h=b();h--;)p=c(),q=b(),q&256&&m.ia.add(p);else if(4===h)for(h=b();h--;)c(),p=c(),q=b(),1==(q&3)&&
m.aa.add(p);else e+=p;return m}function Ka(a){var b=["stackAlloc","stackSave","stackRestore"];return 0==a.indexOf("dynCall_")||b.includes(a)?a:"_"+a}function La(a){for(var b in a)if(a.hasOwnProperty(b)){Q.hasOwnProperty(b)||(Q[b]=a[b]);var c=Ka(b);f.hasOwnProperty(c)||(f[c]=a[b]);"__main_argc_argv"==b&&(f._main=a[b]);}}var Ma={},R=[];function Na(a){var b=R[a];b||(a>=R.length&&(R.length=a+1),R[a]=b=J.get(a));return b}
function Oa(a){return function(){var b=Pa();try{var c=arguments[0],d=Array.prototype.slice.call(arguments,1);if(a.includes("j")){var e=f["dynCall_"+a];var g=d&&d.length?e.apply(null,[c].concat(d)):e.call(null,c);}else g=Na(c).apply(null,d);return g}catch(h){Qa(b);if(h!==h+0)throw h;Ra(1,0);}}}var Sa=1084576;function Ta(a){if(K)return Ua(a);var b=Sa;Sa=a=b+a+15&-16;O.__heap_base.value=a;return b}function Va(a,b){if(S)for(var c=a;c<a+b;c++){var d=Na(c);d&&S.set(d,c);}}var S=void 0,Wa=[];
function Xa(a,b){S||(S=new WeakMap,Va(0,J.length));if(S.has(a))return S.get(a);if(Wa.length)var c=Wa.pop();else {try{J.grow(1);}catch(m){if(!(m instanceof RangeError))throw m;throw "Unable to grow wasm table. Set ALLOW_TABLE_GROWTH.";}c=J.length-1;}try{var d=c;J.set(d,a);R[d]=J.get(d);}catch(m){if(!(m instanceof TypeError))throw m;if("function"==typeof WebAssembly.Function){d=WebAssembly.Function;for(var e={i:"i32",j:"i64",f:"f32",d:"f64",p:"i32"},g={parameters:[],results:"v"==b[0]?[]:[e[b[0]]]},h=1;h<
b.length;++h)g.parameters.push(e[b[h]]);d=new d(g,a);}else {d=[1,96];e=b.slice(0,1);b=b.slice(1);g={i:127,p:127,j:126,f:125,d:124};h=b.length;128>h?d.push(h):d.push(h%128|128,h>>7);for(h=0;h<b.length;++h)d.push(g[b[h]]);"v"==e?d.push(0):d.push(1,g[e]);b=[0,97,115,109,1,0,0,0,1];e=d.length;128>e?b.push(e):b.push(e%128|128,e>>7);b.push.apply(b,d);b.push(2,7,1,1,101,1,102,0,0,7,5,1,1,102,0,0);d=new WebAssembly.Module(new Uint8Array(b));d=(new WebAssembly.Instance(d,{e:{f:a}})).exports.f;}b=c;J.set(b,d);
R[b]=J.get(b);}S.set(a,c);return c}
function Ya(a,b){var c={},d;for(d in a){var e=a[d];"object"==typeof e&&(e=e.value);"number"==typeof e&&(e+=b);c[d]=e;}a=void 0;for(var g in c)!"__cpp_exception __c_longjmp __wasm_apply_data_relocs __dso_handle __tls_size __tls_align __set_stack_limits _emscripten_tls_init __wasm_init_tls __wasm_call_ctors".split(" ").includes(g)&&(b=c[g],g.startsWith("orig$")&&(g=g.split("$")[1],a=!0),O[g]||(O[g]=new WebAssembly.Global({value:"i32",mutable:!0})),a||0==O[g].value)&&("function"==typeof b?O[g].value=
Xa(b):"number"==typeof b?O[g].value=b:"bigint"==typeof b?O[g].value=Number(b):y("unhandled export type for `"+g+"`: "+typeof b));return c}function Za(a,b){var c;b&&(c=Q["orig$"+a]);c||(c=Q[a])&&c.oa&&(c=void 0);c||(c=f[Ka(a)]);!c&&a.startsWith("invoke_")&&(c=Oa(a.split("_")[1]));return c}function $a(a,b){return Math.ceil(a/b)*b}
function ab(a,b){function c(){function e(n){Va(m,d.J);p=Ya(n.exports,h);b.ba||bb();(n=p.__wasm_call_ctors)&&(K?n():ta.push(n));(n=p.__wasm_apply_data_relocs)&&(K?n():xa.push(n));return p}var g=Math.pow(2,d.X);g=Math.max(g,16);var h=d.L?$a(Ta(d.L+g),g):0,m=d.J?J.length:0;g=m+d.J-J.length;0<g&&J.grow(g);var p;g=new Proxy({},{get:function(n,r){switch(r){case "__memory_base":return h;case "__table_base":return m}if(r in Q)return Q[r];if(!(r in n)){var F;n[r]=function(){if(!F){var wa=Za(r,!1);wa||(wa=
p[r]);F=wa;}return F.apply(null,arguments)};}return n[r]}});g={"GOT.mem":new Proxy({},Ia),"GOT.func":new Proxy({},Ia),env:g,qa:g};if(b.A)return a instanceof WebAssembly.Module?(g=new WebAssembly.Instance(a,g),Promise.resolve(e(g))):WebAssembly.instantiate(a,g).then(function(n){return e(n.instance)});var q=a instanceof WebAssembly.Module?a:new WebAssembly.Module(a);g=new WebAssembly.Instance(q,g);return e(g)}var d=Ja(a);Ha=d.aa;if(b.A)return d.B.reduce(function(e,g){return e.then(function(){return cb(g,
b)})},Promise.resolve()).then(function(){return c()});d.B.forEach(function(e){cb(e,b);});return c()}
function cb(a,b){function c(h){if(b.fs&&b.fs.ka(h)){var m=b.fs.readFile(h,{encoding:"binary"});m instanceof Uint8Array||(m=new Uint8Array(m));return b.A?Promise.resolve(m):m}if(b.A)return new Promise(function(p,q){v(h,n=>p(new Uint8Array(n)),q);});if(!w)throw Error(h+": file not found, and synchronous loading of external files is not available");return w(h)}function d(){if("undefined"!=typeof preloadedWasm&&preloadedWasm[a]){var h=preloadedWasm[a];return b.A?Promise.resolve(h):h}return b.A?c(a).then(function(m){return ab(m,
b)}):ab(c(a),b)}function e(h){g.global&&La(h);g.module=h;}b=b||{global:!0,M:!0};var g=Ma[a];if(g)return b.global&&!g.global&&(g.global=!0,"loading"!==g.module&&La(g.module)),b.M&&Infinity!==g.P&&(g.P=Infinity),g.P++,b.A?Promise.resolve(!0):!0;g={P:b.M?Infinity:1,name:a,module:"loading",global:b.global};Ma[a]=g;if(b.A)return d().then(function(h){e(h);return !0});e(d());return !0}
function bb(){for(var a in O)if(0==O[a].value){var b=Za(a,!0);if(b||O[a].required)if("function"==typeof b)O[a].value=Xa(b,b.F);else if("number"==typeof b)O[a].value=b;else throw Error("bad export type for `"+a+"`: "+typeof b);}}function db(){z.length?(Aa(),z.reduce(function(a,b){return a.then(function(){return cb(b,{A:!0,global:!0,M:!0,ba:!0})})},Promise.resolve()).then(function(){bb();Ba();})):bb();}
function eb(a,b,c,d){B("Assertion failed: "+(a?D(H,a):"")+", at: "+[b?b?D(H,b):"":"unknown filename",c,d?d?D(H,d):"":"unknown function"]);}eb.F="vppip";var fb=new WebAssembly.Global({value:"i32",mutable:!1},1024),gb=new WebAssembly.Global({value:"i32",mutable:!0},1084576),hb=new WebAssembly.Global({value:"i32",mutable:!1},1);function ib(){B("");}ib.F="v";var jb=[];
function kb(a,b,c){a-=1024;jb.length=0;var d;for(c>>=2;d=H[b++];)c+=105!=d&c,jb.push(105==d?I[c]:pa[c++>>1]),++c;return Ga[a].apply(null,jb)}kb.F="ippp";function lb(a,b,c){H.copyWithin(a,b,b+c);}lb.F="vppp";
function mb(a){var b=H.length;a>>>=0;if(104857600<a)return !1;for(var c=1;4>=c;c*=2){var d=b*(1+.2/c);d=Math.min(d,a+100663296);var e=Math;d=Math.max(a,d);e=e.min.call(e,104857600,d+(65536-d%65536)%65536);a:{try{C.grow(e-E.byteLength+65535>>>16);qa(C.buffer);var g=1;break a}catch(h){}g=void 0;}if(g)return !0}return !1}mb.F="ip";
var nb=(a,b)=>{for(var c=0,d=a.length-1;0<=d;d--){var e=a[d];"."===e?a.splice(d,1):".."===e?(a.splice(d,1),c++):c&&(a.splice(d,1),c--);}if(b)for(;c;c--)a.unshift("..");return a},ob=a=>{var b="/"===a.charAt(0),c="/"===a.substr(-1);(a=nb(a.split("/").filter(d=>!!d),!b).join("/"))||b||(a=".");a&&c&&(a+="/");return (b?"/":"")+a},pb=a=>{var b=/^(\/?|)([\s\S]*?)((?:\.{1,2}|[^\/]+?|)(\.[^.\/]*|))(?:[\/]*)$/.exec(a).slice(1);a=b[0];b=b[1];if(!a&&!b)return ".";b&&(b=b.substr(0,b.length-1));return a+b},qb=a=>
{if("/"===a)return "/";a=ob(a);a=a.replace(/\/$/,"");var b=a.lastIndexOf("/");return -1===b?a:a.substr(b+1)};function rb(){if("object"==typeof crypto&&"function"==typeof crypto.getRandomValues){var a=new Uint8Array(1);return ()=>{crypto.getRandomValues(a);return a[0]}}if(t)try{var b=require("crypto");return ()=>b.randomBytes(1)[0]}catch(c){}return ()=>B("randomDevice")}
function sb(){for(var a="",b=!1,c=arguments.length-1;-1<=c&&!b;c--){b=0<=c?arguments[c]:"/";if("string"!=typeof b)throw new TypeError("Arguments to path.resolve must be strings");if(!b)return "";a=b+"/"+a;b="/"===b.charAt(0);}a=nb(a.split("/").filter(d=>!!d),!b).join("/");return (b?"/":"")+a||"."}var tb=[];function ub(a,b){tb[a]={input:[],output:[],C:b};vb(a,wb);}
var wb={open:function(a){var b=tb[a.node.rdev];if(!b)throw new T(43);a.tty=b;a.seekable=!1;},close:function(a){a.tty.C.flush(a.tty);},flush:function(a){a.tty.C.flush(a.tty);},read:function(a,b,c,d){if(!a.tty||!a.tty.C.W)throw new T(60);for(var e=0,g=0;g<d;g++){try{var h=a.tty.C.W(a.tty);}catch(m){throw new T(29);}if(void 0===h&&0===e)throw new T(6);if(null===h||void 0===h)break;e++;b[c+g]=h;}e&&(a.node.timestamp=Date.now());return e},write:function(a,b,c,d){if(!a.tty||!a.tty.C.N)throw new T(60);try{for(var e=
0;e<d;e++)a.tty.C.N(a.tty,b[c+e]);}catch(g){throw new T(29);}d&&(a.node.timestamp=Date.now());return e}},xb={W:function(a){if(!a.input.length){var b=null;if(t){var c=Buffer.alloc(256),d=0;try{d=fs.readSync(process.stdin.fd,c,0,256,-1);}catch(e){if(e.toString().includes("EOF"))d=0;else throw e;}0<d?b=c.slice(0,d).toString("utf-8"):b=null;}else "undefined"!=typeof window&&"function"==typeof window.prompt?(b=window.prompt("Input: "),null!==b&&(b+="\n")):"function"==typeof readline&&(b=readline(),null!==
b&&(b+="\n"));if(!b)return null;c=Array(oa(b)+1);b=na(b,c,0,c.length);c.length=b;a.input=c;}return a.input.shift()},N:function(a,b){null===b||10===b?(ka(D(a.output,0)),a.output=[]):0!=b&&a.output.push(b);},flush:function(a){a.output&&0<a.output.length&&(ka(D(a.output,0)),a.output=[]);}},yb={N:function(a,b){null===b||10===b?(y(D(a.output,0)),a.output=[]):0!=b&&a.output.push(b);},flush:function(a){a.output&&0<a.output.length&&(y(D(a.output,0)),a.output=[]);}},U={o:null,u:function(){return U.createNode(null,
"/",16895,0)},createNode:function(a,b,c,d){if(24576===(c&61440)||4096===(c&61440))throw new T(63);U.o||(U.o={dir:{node:{v:U.h.v,s:U.h.s,lookup:U.h.lookup,H:U.h.H,rename:U.h.rename,unlink:U.h.unlink,rmdir:U.h.rmdir,readdir:U.h.readdir,symlink:U.h.symlink},stream:{D:U.l.D}},file:{node:{v:U.h.v,s:U.h.s},stream:{D:U.l.D,read:U.l.read,write:U.l.write,R:U.l.R,Y:U.l.Y,$:U.l.$}},link:{node:{v:U.h.v,s:U.h.s,readlink:U.h.readlink},stream:{}},S:{node:{v:U.h.v,s:U.h.s},stream:zb}});c=Ab(a,b,c,d);16384===(c.mode&
61440)?(c.h=U.o.dir.node,c.l=U.o.dir.stream,c.g={}):32768===(c.mode&61440)?(c.h=U.o.file.node,c.l=U.o.file.stream,c.m=0,c.g=null):40960===(c.mode&61440)?(c.h=U.o.link.node,c.l=U.o.link.stream):8192===(c.mode&61440)&&(c.h=U.o.S.node,c.l=U.o.S.stream);c.timestamp=Date.now();a&&(a.g[b]=c,a.timestamp=c.timestamp);return c},la:function(a){return a.g?a.g.subarray?a.g.subarray(0,a.m):new Uint8Array(a.g):new Uint8Array(0)},T:function(a,b){var c=a.g?a.g.length:0;c>=b||(b=Math.max(b,c*(1048576>c?2:1.125)>>>
0),0!=c&&(b=Math.max(b,256)),c=a.g,a.g=new Uint8Array(b),0<a.m&&a.g.set(c.subarray(0,a.m),0));},ga:function(a,b){if(a.m!=b)if(0==b)a.g=null,a.m=0;else {var c=a.g;a.g=new Uint8Array(b);c&&a.g.set(c.subarray(0,Math.min(b,a.m)));a.m=b;}},h:{v:function(a){var b={};b.dev=8192===(a.mode&61440)?a.id:1;b.ino=a.id;b.mode=a.mode;b.nlink=1;b.uid=0;b.gid=0;b.rdev=a.rdev;16384===(a.mode&61440)?b.size=4096:32768===(a.mode&61440)?b.size=a.m:40960===(a.mode&61440)?b.size=a.link.length:b.size=0;b.atime=new Date(a.timestamp);
b.mtime=new Date(a.timestamp);b.ctime=new Date(a.timestamp);b.da=4096;b.blocks=Math.ceil(b.size/b.da);return b},s:function(a,b){void 0!==b.mode&&(a.mode=b.mode);void 0!==b.timestamp&&(a.timestamp=b.timestamp);void 0!==b.size&&U.ga(a,b.size);},lookup:function(){throw Bb[44];},H:function(a,b,c,d){return U.createNode(a,b,c,d)},rename:function(a,b,c){if(16384===(a.mode&61440)){try{var d=Cb(b,c);}catch(g){}if(d)for(var e in d.g)throw new T(55);}delete a.parent.g[a.name];a.parent.timestamp=Date.now();a.name=
c;b.g[c]=a;b.timestamp=a.parent.timestamp;a.parent=b;},unlink:function(a,b){delete a.g[b];a.timestamp=Date.now();},rmdir:function(a,b){var c=Cb(a,b),d;for(d in c.g)throw new T(55);delete a.g[b];a.timestamp=Date.now();},readdir:function(a){var b=[".",".."],c;for(c in a.g)a.g.hasOwnProperty(c)&&b.push(c);return b},symlink:function(a,b,c){a=U.createNode(a,b,41471,0);a.link=c;return a},readlink:function(a){if(40960!==(a.mode&61440))throw new T(28);return a.link}},l:{read:function(a,b,c,d,e){var g=a.node.g;
if(e>=a.node.m)return 0;a=Math.min(a.node.m-e,d);if(8<a&&g.subarray)b.set(g.subarray(e,e+a),c);else for(d=0;d<a;d++)b[c+d]=g[e+d];return a},write:function(a,b,c,d,e,g){b.buffer===G.buffer&&(g=!1);if(!d)return 0;a=a.node;a.timestamp=Date.now();if(b.subarray&&(!a.g||a.g.subarray)){if(g)return a.g=b.subarray(c,c+d),a.m=d;if(0===a.m&&0===e)return a.g=b.slice(c,c+d),a.m=d;if(e+d<=a.m)return a.g.set(b.subarray(c,c+d),e),d}U.T(a,e+d);if(a.g.subarray&&b.subarray)a.g.set(b.subarray(c,c+d),e);else for(g=0;g<
d;g++)a.g[e+g]=b[c+g];a.m=Math.max(a.m,e+d);return d},D:function(a,b,c){1===c?b+=a.position:2===c&&32768===(a.node.mode&61440)&&(b+=a.node.m);if(0>b)throw new T(28);return b},R:function(a,b,c){U.T(a.node,b+c);a.node.m=Math.max(a.node.m,b+c);},Y:function(a,b,c,d,e){if(32768!==(a.node.mode&61440))throw new T(43);a=a.node.g;if(e&2||a.buffer!==E){if(0<c||c+b<a.length)a.subarray?a=a.subarray(c,c+b):a=Array.prototype.slice.call(a,c,c+b);c=!0;B();b=void 0;if(!b)throw new T(48);G.set(a,b);}else c=!1,b=a.byteOffset;
return {na:b,ja:c}},$:function(a,b,c,d,e){if(32768!==(a.node.mode&61440))throw new T(43);if(e&2)return 0;U.l.write(a,b,0,d,c,!1);return 0}}},Db=null,Eb={},Fb=[],Gb=1,V=null,Hb=!0,T=null,Bb={},W=(a,b={})=>{a=sb("/",a);if(!a)return {path:"",node:null};b=Object.assign({V:!0,O:0},b);if(8<b.O)throw new T(32);a=nb(a.split("/").filter(h=>!!h),!1);for(var c=Db,d="/",e=0;e<a.length;e++){var g=e===a.length-1;if(g&&b.parent)break;c=Cb(c,a[e]);d=ob(d+"/"+a[e]);c.I&&(!g||g&&b.V)&&(c=c.I.root);if(!g||b.U)for(g=0;40960===
(c.mode&61440);)if(c=Ib(d),d=sb(pb(d),c),c=W(d,{O:b.O+1}).node,40<g++)throw new T(32);}return {path:d,node:c}},Jb=a=>{for(var b;;){if(a===a.parent)return a=a.u.Z,b?"/"!==a[a.length-1]?a+"/"+b:a+b:a;b=b?a.name+"/"+b:a.name;a=a.parent;}},Kb=(a,b)=>{for(var c=0,d=0;d<b.length;d++)c=(c<<5)-c+b.charCodeAt(d)|0;return (a+c>>>0)%V.length},Cb=(a,b)=>{var c;if(c=(c=Lb(a,"x"))?c:a.h.lookup?0:2)throw new T(c,a);for(c=V[Kb(a.id,b)];c;c=c.fa){var d=c.name;if(c.parent.id===a.id&&d===b)return c}return a.h.lookup(a,
b)},Ab=(a,b,c,d)=>{a=new Mb(a,b,c,d);b=Kb(a.parent.id,a.name);a.fa=V[b];return V[b]=a},Nb={r:0,"r+":2,w:577,"w+":578,a:1089,"a+":1090},Ob=a=>{var b=["r","w","rw"][a&3];a&512&&(b+="w");return b},Lb=(a,b)=>{if(Hb)return 0;if(!b.includes("r")||a.mode&292){if(b.includes("w")&&!(a.mode&146)||b.includes("x")&&!(a.mode&73))return 2}else return 2;return 0},Pb=(a,b)=>{try{return Cb(a,b),20}catch(c){}return Lb(a,"wx")},Qb=()=>{for(var a=0;4096>=a;a++)if(!Fb[a])return a;throw new T(33);},Rb=a=>{X||(X=function(){this.G=
{};},X.prototype={},Object.defineProperties(X.prototype,{object:{get:function(){return this.node},set:function(c){this.node=c;}},flags:{get:function(){return this.G.flags},set:function(c){this.G.flags=c;}},position:{get:function(){return this.G.position},set:function(c){this.G.position=c;}}}));a=Object.assign(new X,a);var b=Qb();a.fd=b;return Fb[b]=a},zb={open:a=>{a.l=Eb[a.node.rdev].l;a.l.open&&a.l.open(a);},D:()=>{throw new T(70);}},vb=(a,b)=>{Eb[a]={l:b};},Sb=(a,b)=>{var c="/"===b,d=!b;if(c&&Db)throw new T(10);
if(!c&&!d){var e=W(b,{V:!1});b=e.path;e=e.node;if(e.I)throw new T(10);if(16384!==(e.mode&61440))throw new T(54);}b={type:a,ma:{},Z:b,ea:[]};a=a.u(b);a.u=b;b.root=a;c?Db=a:e&&(e.I=b,e.u&&e.u.ea.push(b));},Y=(a,b,c)=>{var d=W(a,{parent:!0}).node;a=qb(a);if(!a||"."===a||".."===a)throw new T(28);var e=Pb(d,a);if(e)throw new T(e);if(!d.h.H)throw new T(63);return d.h.H(d,a,b,c)},Tb=(a,b,c)=>{"undefined"==typeof c&&(c=b,b=438);Y(a,b|8192,c);},Ub=(a,b)=>{if(!sb(a))throw new T(44);var c=W(b,{parent:!0}).node;
if(!c)throw new T(44);b=qb(b);var d=Pb(c,b);if(d)throw new T(d);if(!c.h.symlink)throw new T(63);c.h.symlink(c,b,a);},Ib=a=>{a=W(a).node;if(!a)throw new T(44);if(!a.h.readlink)throw new T(28);return sb(Jb(a.parent),a.h.readlink(a))},Wb=(a,b)=>{if(""===a)throw new T(44);if("string"==typeof b){var c=Nb[b];if("undefined"==typeof c)throw Error("Unknown file open mode: "+b);b=c;}var d=b&64?("undefined"==typeof d?438:d)&4095|32768:0;if("object"==typeof a)var e=a;else {a=ob(a);try{e=W(a,{U:!(b&131072)}).node;}catch(g){}}c=
!1;if(b&64)if(e){if(b&128)throw new T(20);}else e=Y(a,d,0),c=!0;if(!e)throw new T(44);8192===(e.mode&61440)&&(b&=-513);if(b&65536&&16384!==(e.mode&61440))throw new T(54);if(!c&&(d=e?40960===(e.mode&61440)?32:16384===(e.mode&61440)&&("r"!==Ob(b)||b&512)?31:Lb(e,Ob(b)):44))throw new T(d);if(b&512&&!c){d=e;d="string"==typeof d?W(d,{U:!0}).node:d;if(!d.h.s)throw new T(63);if(16384===(d.mode&61440))throw new T(31);if(32768!==(d.mode&61440))throw new T(28);if(c=Lb(d,"w"))throw new T(c);d.h.s(d,{size:0,
timestamp:Date.now()});}b&=-131713;e=Rb({node:e,path:Jb(e),flags:b,seekable:!0,position:0,l:e.l,pa:[],error:!1});e.l.open&&e.l.open(e);!f.logReadFiles||b&1||(Vb||(Vb={}),a in Vb||(Vb[a]=1));},Xb=()=>{T||(T=function(a,b){this.node=b;this.message="FS error";},T.prototype=Error(),T.prototype.constructor=T,[44].forEach(a=>{Bb[a]=new T(a);Bb[a].stack="<generic error, no stack>";}));},Yb,Zb=(a,b)=>{var c=0;a&&(c|=365);b&&(c|=146);return c},Z=(a,b,c)=>{a=ob("/dev/"+a);var d=Zb(!!b,!!c);$b||($b=64);var e=$b++<<
8|0;vb(e,{open:g=>{g.seekable=!1;},close:()=>{c&&c.buffer&&c.buffer.length&&c(10);},read:(g,h,m,p)=>{for(var q=0,n=0;n<p;n++){try{var r=b();}catch(F){throw new T(29);}if(void 0===r&&0===q)throw new T(6);if(null===r||void 0===r)break;q++;h[m+n]=r;}q&&(g.node.timestamp=Date.now());return q},write:(g,h,m,p)=>{for(var q=0;q<p;q++)try{c(h[m+q]);}catch(n){throw new T(29);}p&&(g.node.timestamp=Date.now());return q}});Tb(a,d,e);},$b,X,Vb;
function ac(a){if(!noExitRuntime){if(f.onExit)f.onExit(a);la=!0;}k(a,new ja(a));}function Mb(a,b,c,d){a||(a=this);this.parent=a;this.u=a.u;this.I=null;this.id=Gb++;this.name=b;this.mode=c;this.h={};this.l={};this.rdev=d;}Object.defineProperties(Mb.prototype,{read:{get:function(){return 365===(this.mode&365)},set:function(a){a?this.mode|=365:this.mode&=-366;}},write:{get:function(){return 146===(this.mode&146)},set:function(a){a?this.mode|=146:this.mode&=-147;}}});Xb();V=Array(4096);Sb(U,"/");
Y("/tmp",16895,0);Y("/home",16895,0);Y("/home/web_user",16895,0);(()=>{Y("/dev",16895,0);vb(259,{read:()=>0,write:(b,c,d,e)=>e});Tb("/dev/null",259);ub(1280,xb);ub(1536,yb);Tb("/dev/tty",1280);Tb("/dev/tty1",1536);var a=rb();Z("random",a);Z("urandom",a);Y("/dev/shm",16895,0);Y("/dev/shm/tmp",16895,0);})();
(()=>{Y("/proc",16895,0);var a=Y("/proc/self",16895,0);Y("/proc/self/fd",16895,0);Sb({u:()=>{var b=Ab(a,"fd",16895,73);b.h={lookup:(c,d)=>{var e=Fb[+d];if(!e)throw new T(8);c={parent:null,u:{Z:"fake"},h:{readlink:()=>e.path}};return c.parent=c}};return b}},"/proc/self/fd");})();var Q={__assert_fail:eb,__heap_base:Sa,__indirect_function_table:J,__memory_base:fb,__stack_pointer:gb,__table_base:hb,abort:ib,emscripten_asm_const_int:kb,emscripten_memcpy_big:lb,emscripten_resize_heap:mb,memory:C};
(function(){function a(e,g){e=e.exports;e=Ya(e,1024);f.asm=e;g=Ja(g);g.B&&(z=g.B.concat(z));La(e);ta.unshift(f.asm.__wasm_call_ctors);xa.push(f.asm.__wasm_apply_data_relocs);Ba();}function b(e){a(e.instance,e.module);}function c(e){return Fa().then(function(g){return WebAssembly.instantiate(g,d)}).then(function(g){return g}).then(e,function(g){y("failed to asynchronously prepare wasm: "+g);B(g);})}var d={env:Q,wasi_snapshot_preview1:Q,"GOT.mem":new Proxy(Q,Ia),"GOT.func":new Proxy(Q,Ia)};Aa();if(f.instantiateWasm)try{return f.instantiateWasm(d,
a)}catch(e){return y("Module.instantiateWasm callback failed with error: "+e),!1}(function(){return A||"function"!=typeof WebAssembly.instantiateStreaming||Ca()||N.startsWith("file://")||t||"function"!=typeof fetch?c(b):fetch(N,{credentials:"same-origin"}).then(function(e){return WebAssembly.instantiateStreaming(e,d).then(b,function(g){y("wasm streaming compile failed: "+g);y("falling back to ArrayBuffer instantiation");return c(b)})})})().catch(ba);return {}})();
f.___wasm_call_ctors=function(){return (f.___wasm_call_ctors=f.asm.__wasm_call_ctors).apply(null,arguments)};f.___wasm_apply_data_relocs=function(){return (f.___wasm_apply_data_relocs=f.asm.__wasm_apply_data_relocs).apply(null,arguments)};var Ua=f._malloc=function(){return (Ua=f._malloc=f.asm.malloc).apply(null,arguments)};f._sha512=function(){return (f._sha512=f.asm.sha512).apply(null,arguments)};f._random_bytes=function(){return (f._random_bytes=f.asm.random_bytes).apply(null,arguments)};
f._argon2=function(){return (f._argon2=f.asm.argon2).apply(null,arguments)};f._new_keypair=function(){return (f._new_keypair=f.asm.new_keypair).apply(null,arguments)};f._keypair_from_seed=function(){return (f._keypair_from_seed=f.asm.keypair_from_seed).apply(null,arguments)};f._keypair_from_secret_key=function(){return (f._keypair_from_secret_key=f.asm.keypair_from_secret_key).apply(null,arguments)};f._sign_data=function(){return (f._sign_data=f.asm.sign_data).apply(null,arguments)};
f._verify_data=function(){return (f._verify_data=f.asm.verify_data).apply(null,arguments)};f._calculate_nonce=function(){return (f._calculate_nonce=f.asm.calculate_nonce).apply(null,arguments)};f._encrypt_data=function(){return (f._encrypt_data=f.asm.encrypt_data).apply(null,arguments)};f._decrypt_data=function(){return (f._decrypt_data=f.asm.decrypt_data).apply(null,arguments)};
var Ra=f._setThrew=function(){return (Ra=f._setThrew=f.asm.setThrew).apply(null,arguments)},Pa=f.stackSave=function(){return (Pa=f.stackSave=f.asm.stackSave).apply(null,arguments)},Qa=f.stackRestore=function(){return (Qa=f.stackRestore=f.asm.stackRestore).apply(null,arguments)},bc=f.stackAlloc=function(){return (bc=f.stackAlloc=f.asm.stackAlloc).apply(null,arguments)};f.dynCall_iiiji=function(){return (f.dynCall_iiiji=f.asm.dynCall_iiiji).apply(null,arguments)};
f.dynCall_iiij=function(){return (f.dynCall_iiij=f.asm.dynCall_iiij).apply(null,arguments)};f.dynCall_iijii=function(){return (f.dynCall_iijii=f.asm.dynCall_iijii).apply(null,arguments)};f.dynCall_iiijiji=function(){return (f.dynCall_iiijiji=f.asm.dynCall_iiijiji).apply(null,arguments)};f.dynCall_iiijiii=function(){return (f.dynCall_iiijiii=f.asm.dynCall_iiijiii).apply(null,arguments)};var cc;M=function dc(){cc||ec();cc||(M=dc);};
function fc(a){var b=f._main;if(b){a=a||[];a.unshift(ea);var c=a.length,d=bc(4*(c+1)),e=d>>2;a.forEach(h=>{var m=I,p=e++,q=oa(h)+1,n=bc(q);na(h,G,n,q);m[p]=n;});I[e]=0;try{var g=b(c,d);ac(g);}catch(h){h instanceof ja||"unwind"==h||k(1,h);}}}var gc=!1;
function ec(){function a(){if(!cc&&(cc=!0,f.calledRun=!0,!la)){K=!0;P(xa);f.noFSInit||Yb||(Yb=!0,Xb(),f.stdin=f.stdin,f.stdout=f.stdout,f.stderr=f.stderr,f.stdin?Z("stdin",f.stdin):Ub("/dev/tty","/dev/stdin"),f.stdout?Z("stdout",null,f.stdout):Ub("/dev/tty","/dev/stdout"),f.stderr?Z("stderr",null,f.stderr):Ub("/dev/tty1","/dev/stderr"),Wb("/dev/stdin",0),Wb("/dev/stdout",1),Wb("/dev/stderr",1));Hb=!1;P(ta);P(ua);aa(f);if(f.onRuntimeInitialized)f.onRuntimeInitialized();hc&&fc(b);if(f.postRun)for("function"==
typeof f.postRun&&(f.postRun=[f.postRun]);f.postRun.length;){var c=f.postRun.shift();va.unshift(c);}P(va);}}var b=b||da;if(!(0<L)){if(!gc&&(db(),gc=!0,0<L))return;if(f.preRun)for("function"==typeof f.preRun&&(f.preRun=[f.preRun]);f.preRun.length;)ya();P(sa);0<L||(f.setStatus?(f.setStatus("Running..."),setTimeout(function(){setTimeout(function(){f.setStatus("");},1);a();},1)):a());}}if(f.preInit)for("function"==typeof f.preInit&&(f.preInit=[f.preInit]);0<f.preInit.length;)f.preInit.pop()();var hc=!0;
f.noInitialRun&&(hc=!1);ec();


  return libsodiumMethodsModule.ready
}
);
})();

// Copyright (C) 2022 Deliberative Technologies P.C.
const newKeyPair = async (module) => {
    const wasmMemory = module
        ? module.wasmMemory
        : memory$3.newKeyPairMemory();
    let offset = 0;
    const publicKey = new Uint8Array(wasmMemory.buffer, offset, crypto_sign_ed25519_PUBLICKEYBYTES);
    offset += crypto_sign_ed25519_PUBLICKEYBYTES;
    const secretKey = new Uint8Array(wasmMemory.buffer, offset, crypto_sign_ed25519_SECRETKEYBYTES);
    const libsodiumModule = await libsodiumMethodsModule({ wasmMemory });
    const result = libsodiumModule._new_keypair(publicKey.byteOffset, secretKey.byteOffset);
    switch (result) {
        case 0: {
            return { publicKey, secretKey };
        }
        default: {
            throw new Error("An unexpected error occured.");
        }
    }
};
const keyPairFromSeed = async (seed, module) => {
    const wasmMemory = module
        ? module.wasmMemory
        : memory$3.keyPairFromSeedMemory();
    let offset = 0;
    const publicKey = new Uint8Array(wasmMemory.buffer, offset, crypto_sign_ed25519_PUBLICKEYBYTES);
    offset += crypto_sign_ed25519_PUBLICKEYBYTES;
    const secretKey = new Uint8Array(wasmMemory.buffer, offset, crypto_sign_ed25519_SECRETKEYBYTES);
    offset += crypto_sign_ed25519_SECRETKEYBYTES;
    const seedBytes = new Uint8Array(wasmMemory.buffer, offset, crypto_sign_ed25519_SEEDBYTES);
    seedBytes.set([...seed]);
    const libsodiumModule = module || (await libsodiumMethodsModule({ wasmMemory }));
    const result = libsodiumModule._keypair_from_seed(publicKey.byteOffset, secretKey.byteOffset, seedBytes.byteOffset);
    switch (result) {
        case 0: {
            return { publicKey, secretKey };
        }
        default: {
            throw new Error("An unexpected error occured.");
        }
    }
};
const keyPairFromSecretKey = async (secretKey, module) => {
    const wasmMemory = module
        ? module.wasmMemory
        : memory$3.keyPairFromSecretKeyMemory();
    let offset = 0;
    const publicKey = new Uint8Array(wasmMemory.buffer, offset, crypto_sign_ed25519_PUBLICKEYBYTES);
    offset += crypto_sign_ed25519_PUBLICKEYBYTES;
    const sk = new Uint8Array(wasmMemory.buffer, offset, crypto_sign_ed25519_SECRETKEYBYTES);
    sk.set([...secretKey]);
    const libsodiumModule = await libsodiumMethodsModule({ wasmMemory });
    const result = libsodiumModule._keypair_from_secret_key(publicKey.byteOffset, secretKey.byteOffset);
    switch (result) {
        case 0: {
            return { publicKey, secretKey };
        }
        default: {
            throw new Error("An unexpected error occured.");
        }
    }
};
var keyPair = {
    newKeyPair,
    keyPairFromSeed,
    keyPairFromSecretKey,
};

// Copyright (C) 2022 Deliberative Technologies P.C.
/**
 * @function
 * Returns the signature of the data provided.
 */
const sign = async (message, secretKey, module) => {
    const messageLen = message.length;
    const wasmMemory = module
        ? module.wasmMemory
        : memory$3.signMemory(messageLen);
    let offset = 0;
    const dataArray = new Uint8Array(wasmMemory.buffer, offset, messageLen);
    dataArray.set([...message]);
    offset += messageLen;
    const signature = new Uint8Array(wasmMemory.buffer, offset, crypto_sign_ed25519_BYTES);
    offset += crypto_sign_ed25519_BYTES;
    const sk = new Uint8Array(wasmMemory.buffer, offset, crypto_sign_ed25519_SECRETKEYBYTES);
    sk.set([...secretKey]);
    const libsodiumModule = module || (await libsodiumMethodsModule({ wasmMemory }));
    libsodiumModule._sign_data(messageLen, dataArray.byteOffset, signature.byteOffset, sk.byteOffset);
    return new Uint8Array([...signature]);
};

// Copyright (C) 2022 Deliberative Technologies P.C.
const verify = async (message, signature, publicKey, module) => {
    const len = message.length;
    const wasmMemory = module
        ? module.wasmMemory
        : memory$3.verifyMemory(len);
    let offset = 0;
    const dataArray = new Uint8Array(wasmMemory.buffer, offset, len);
    dataArray.set([...message]);
    offset += len;
    const sig = new Uint8Array(wasmMemory.buffer, offset, crypto_sign_ed25519_BYTES);
    sig.set([...signature]);
    offset += crypto_sign_ed25519_BYTES;
    const key = new Uint8Array(wasmMemory.buffer, offset, crypto_sign_ed25519_PUBLICKEYBYTES);
    key.set([...publicKey]);
    const libsodiumModule = await libsodiumMethodsModule({ wasmMemory });
    const result = libsodiumModule._verify_data(len, dataArray.byteOffset, sig.byteOffset, key.byteOffset);
    return result === 0;
};

// Copyright (C) 2022 Deliberative Technologies P.C.
const encrypt = async (message, publicKey, additionalData, module) => {
    const len = message.length;
    const additionalLen = additionalData.length;
    const wasmMemory = module
        ? module.wasmMemory
        : memory$3.encryptMemory(len, additionalLen);
    const sealedBoxLen = crypto_box_x25519_PUBLICKEYBYTES + // ephemeral x25519 public key
        crypto_box_x25519_NONCEBYTES + // xchacha uses 24 byte nonce while ietf 12
        len +
        crypto_box_poly1305_AUTHTAGBYTES; // 16 bytes poly1305 auth tag
    let offset = 0;
    const dataArray = new Uint8Array(wasmMemory.buffer, offset, len);
    dataArray.set([...message]);
    offset += len;
    const pub = new Uint8Array(wasmMemory.buffer, offset, crypto_sign_ed25519_PUBLICKEYBYTES);
    pub.set([...publicKey]);
    offset += crypto_sign_ed25519_PUBLICKEYBYTES;
    const additional = new Uint8Array(wasmMemory.buffer, offset, additionalLen);
    additional.set([...additionalData]);
    offset += additionalLen;
    const encrypted = new Uint8Array(wasmMemory.buffer, offset, sealedBoxLen * Uint8Array.BYTES_PER_ELEMENT);
    const libsodiumModule = module || (await libsodiumMethodsModule({ wasmMemory }));
    const result = libsodiumModule._encrypt_data(len, dataArray.byteOffset, pub.byteOffset, additionalLen, additional.byteOffset, encrypted.byteOffset);
    switch (result) {
        case 0: {
            return new Uint8Array([...encrypted]);
        }
        case -1: {
            throw new Error("Could not convert Ed25519 public key to X25519.");
        }
        case -2: {
            throw new Error("Could not create a shared secret.");
        }
        default:
            throw new Error("An unexpected error occured.");
    }
};

// Copyright (C) 2022 Deliberative Technologies P.C.
const decrypt = async (encrypted, secretKey, additionalData, module) => {
    const len = encrypted.length;
    const additionalLen = additionalData.length;
    const wasmMemory = module
        ? module.wasmMemory
        : memory$3.decryptMemory(len, additionalLen);
    const decryptedLen = len -
        crypto_box_x25519_PUBLICKEYBYTES - // x25519 ephemeral
        crypto_box_x25519_NONCEBYTES - // nonce
        crypto_box_poly1305_AUTHTAGBYTES; // authTag
    let offset = 0;
    const encryptedArray = new Uint8Array(wasmMemory.buffer, offset, len);
    encryptedArray.set([...encrypted]);
    offset += len;
    const sec = new Uint8Array(wasmMemory.buffer, offset, crypto_sign_ed25519_SECRETKEYBYTES);
    sec.set([...secretKey]);
    offset += crypto_sign_ed25519_SECRETKEYBYTES;
    const additional = new Uint8Array(wasmMemory.buffer, offset, additionalLen);
    additional.set([...additionalData]);
    offset += additionalLen;
    const decrypted = new Uint8Array(wasmMemory.buffer, offset, decryptedLen * Uint8Array.BYTES_PER_ELEMENT);
    const libsodiumModule = module || (await libsodiumMethodsModule({ wasmMemory }));
    const result = libsodiumModule._decrypt_data(len, encryptedArray.byteOffset, sec.byteOffset, additionalLen, additional.byteOffset, decrypted.byteOffset);
    switch (result) {
        case 0:
            return decrypted;
        case -1:
            throw new Error("Decrypted data len will be <= 0.");
        case -2:
            throw new Error("Could not create successful key exchange");
        case -3:
            throw new Error("Invalid ephemeral key signature");
        case -4:
            throw new Error("Unsuccessful decryption attempt");
        default:
            throw new Error("Unexpected error occured");
    }
};

// Copyright (C) 2022 Deliberative Technologies P.C.
var asymmetric = {
    keyPair,
    sign,
    verify,
    encrypt,
    decrypt,
    memory: memory$3,
};

var wordlist = ["abandon","ability","able","about","above","absent","absorb","abstract","absurd","abuse","access","accident","account","accuse","achieve","acid","acoustic","acquire","across","act","action","actor","actress","actual","adapt","add","addict","address","adjust","admit","adult","advance","advice","aerobic","affair","afford","afraid","again","age","agent","agree","ahead","aim","air","airport","aisle","alarm","album","alcohol","alert","alien","all","alley","allow","almost","alone","alpha","already","also","alter","always","amateur","amazing","among","amount","amused","analyst","anchor","ancient","anger","angle","angry","animal","ankle","announce","annual","another","answer","antenna","antique","anxiety","any","apart","apology","appear","apple","approve","april","arch","arctic","area","arena","argue","arm","armed","armor","army","around","arrange","arrest","arrive","arrow","art","artefact","artist","artwork","ask","aspect","assault","asset","assist","assume","asthma","athlete","atom","attack","attend","attitude","attract","auction","audit","august","aunt","author","auto","autumn","average","avocado","avoid","awake","aware","away","awesome","awful","awkward","axis","baby","bachelor","bacon","badge","bag","balance","balcony","ball","bamboo","banana","banner","bar","barely","bargain","barrel","base","basic","basket","battle","beach","bean","beauty","because","become","beef","before","begin","behave","behind","believe","below","belt","bench","benefit","best","betray","better","between","beyond","bicycle","bid","bike","bind","biology","bird","birth","bitter","black","blade","blame","blanket","blast","bleak","bless","blind","blood","blossom","blouse","blue","blur","blush","board","boat","body","boil","bomb","bone","bonus","book","boost","border","boring","borrow","boss","bottom","bounce","box","boy","bracket","brain","brand","brass","brave","bread","breeze","brick","bridge","brief","bright","bring","brisk","broccoli","broken","bronze","broom","brother","brown","brush","bubble","buddy","budget","buffalo","build","bulb","bulk","bullet","bundle","bunker","burden","burger","burst","bus","business","busy","butter","buyer","buzz","cabbage","cabin","cable","cactus","cage","cake","call","calm","camera","camp","can","canal","cancel","candy","cannon","canoe","canvas","canyon","capable","capital","captain","car","carbon","card","cargo","carpet","carry","cart","case","cash","casino","castle","casual","cat","catalog","catch","category","cattle","caught","cause","caution","cave","ceiling","celery","cement","census","century","cereal","certain","chair","chalk","champion","change","chaos","chapter","charge","chase","chat","cheap","check","cheese","chef","cherry","chest","chicken","chief","child","chimney","choice","choose","chronic","chuckle","chunk","churn","cigar","cinnamon","circle","citizen","city","civil","claim","clap","clarify","claw","clay","clean","clerk","clever","click","client","cliff","climb","clinic","clip","clock","clog","close","cloth","cloud","clown","club","clump","cluster","clutch","coach","coast","coconut","code","coffee","coil","coin","collect","color","column","combine","come","comfort","comic","common","company","concert","conduct","confirm","congress","connect","consider","control","convince","cook","cool","copper","copy","coral","core","corn","correct","cost","cotton","couch","country","couple","course","cousin","cover","coyote","crack","cradle","craft","cram","crane","crash","crater","crawl","crazy","cream","credit","creek","crew","cricket","crime","crisp","critic","crop","cross","crouch","crowd","crucial","cruel","cruise","crumble","crunch","crush","cry","crystal","cube","culture","cup","cupboard","curious","current","curtain","curve","cushion","custom","cute","cycle","dad","damage","damp","dance","danger","daring","dash","daughter","dawn","day","deal","debate","debris","decade","december","decide","decline","decorate","decrease","deer","defense","define","defy","degree","delay","deliver","demand","demise","denial","dentist","deny","depart","depend","deposit","depth","deputy","derive","describe","desert","design","desk","despair","destroy","detail","detect","develop","device","devote","diagram","dial","diamond","diary","dice","diesel","diet","differ","digital","dignity","dilemma","dinner","dinosaur","direct","dirt","disagree","discover","disease","dish","dismiss","disorder","display","distance","divert","divide","divorce","dizzy","doctor","document","dog","doll","dolphin","domain","donate","donkey","donor","door","dose","double","dove","draft","dragon","drama","drastic","draw","dream","dress","drift","drill","drink","drip","drive","drop","drum","dry","duck","dumb","dune","during","dust","dutch","duty","dwarf","dynamic","eager","eagle","early","earn","earth","easily","east","easy","echo","ecology","economy","edge","edit","educate","effort","egg","eight","either","elbow","elder","electric","elegant","element","elephant","elevator","elite","else","embark","embody","embrace","emerge","emotion","employ","empower","empty","enable","enact","end","endless","endorse","enemy","energy","enforce","engage","engine","enhance","enjoy","enlist","enough","enrich","enroll","ensure","enter","entire","entry","envelope","episode","equal","equip","era","erase","erode","erosion","error","erupt","escape","essay","essence","estate","eternal","ethics","evidence","evil","evoke","evolve","exact","example","excess","exchange","excite","exclude","excuse","execute","exercise","exhaust","exhibit","exile","exist","exit","exotic","expand","expect","expire","explain","expose","express","extend","extra","eye","eyebrow","fabric","face","faculty","fade","faint","faith","fall","false","fame","family","famous","fan","fancy","fantasy","farm","fashion","fat","fatal","father","fatigue","fault","favorite","feature","february","federal","fee","feed","feel","female","fence","festival","fetch","fever","few","fiber","fiction","field","figure","file","film","filter","final","find","fine","finger","finish","fire","firm","first","fiscal","fish","fit","fitness","fix","flag","flame","flash","flat","flavor","flee","flight","flip","float","flock","floor","flower","fluid","flush","fly","foam","focus","fog","foil","fold","follow","food","foot","force","forest","forget","fork","fortune","forum","forward","fossil","foster","found","fox","fragile","frame","frequent","fresh","friend","fringe","frog","front","frost","frown","frozen","fruit","fuel","fun","funny","furnace","fury","future","gadget","gain","galaxy","gallery","game","gap","garage","garbage","garden","garlic","garment","gas","gasp","gate","gather","gauge","gaze","general","genius","genre","gentle","genuine","gesture","ghost","giant","gift","giggle","ginger","giraffe","girl","give","glad","glance","glare","glass","glide","glimpse","globe","gloom","glory","glove","glow","glue","goat","goddess","gold","good","goose","gorilla","gospel","gossip","govern","gown","grab","grace","grain","grant","grape","grass","gravity","great","green","grid","grief","grit","grocery","group","grow","grunt","guard","guess","guide","guilt","guitar","gun","gym","habit","hair","half","hammer","hamster","hand","happy","harbor","hard","harsh","harvest","hat","have","hawk","hazard","head","health","heart","heavy","hedgehog","height","hello","helmet","help","hen","hero","hidden","high","hill","hint","hip","hire","history","hobby","hockey","hold","hole","holiday","hollow","home","honey","hood","hope","horn","horror","horse","hospital","host","hotel","hour","hover","hub","huge","human","humble","humor","hundred","hungry","hunt","hurdle","hurry","hurt","husband","hybrid","ice","icon","idea","identify","idle","ignore","ill","illegal","illness","image","imitate","immense","immune","impact","impose","improve","impulse","inch","include","income","increase","index","indicate","indoor","industry","infant","inflict","inform","inhale","inherit","initial","inject","injury","inmate","inner","innocent","input","inquiry","insane","insect","inside","inspire","install","intact","interest","into","invest","invite","involve","iron","island","isolate","issue","item","ivory","jacket","jaguar","jar","jazz","jealous","jeans","jelly","jewel","job","join","joke","journey","joy","judge","juice","jump","jungle","junior","junk","just","kangaroo","keen","keep","ketchup","key","kick","kid","kidney","kind","kingdom","kiss","kit","kitchen","kite","kitten","kiwi","knee","knife","knock","know","lab","label","labor","ladder","lady","lake","lamp","language","laptop","large","later","latin","laugh","laundry","lava","law","lawn","lawsuit","layer","lazy","leader","leaf","learn","leave","lecture","left","leg","legal","legend","leisure","lemon","lend","length","lens","leopard","lesson","letter","level","liar","liberty","library","license","life","lift","light","like","limb","limit","link","lion","liquid","list","little","live","lizard","load","loan","lobster","local","lock","logic","lonely","long","loop","lottery","loud","lounge","love","loyal","lucky","luggage","lumber","lunar","lunch","luxury","lyrics","machine","mad","magic","magnet","maid","mail","main","major","make","mammal","man","manage","mandate","mango","mansion","manual","maple","marble","march","margin","marine","market","marriage","mask","mass","master","match","material","math","matrix","matter","maximum","maze","meadow","mean","measure","meat","mechanic","medal","media","melody","melt","member","memory","mention","menu","mercy","merge","merit","merry","mesh","message","metal","method","middle","midnight","milk","million","mimic","mind","minimum","minor","minute","miracle","mirror","misery","miss","mistake","mix","mixed","mixture","mobile","model","modify","mom","moment","monitor","monkey","monster","month","moon","moral","more","morning","mosquito","mother","motion","motor","mountain","mouse","move","movie","much","muffin","mule","multiply","muscle","museum","mushroom","music","must","mutual","myself","mystery","myth","naive","name","napkin","narrow","nasty","nation","nature","near","neck","need","negative","neglect","neither","nephew","nerve","nest","net","network","neutral","never","news","next","nice","night","noble","noise","nominee","noodle","normal","north","nose","notable","note","nothing","notice","novel","now","nuclear","number","nurse","nut","oak","obey","object","oblige","obscure","observe","obtain","obvious","occur","ocean","october","odor","off","offer","office","often","oil","okay","old","olive","olympic","omit","once","one","onion","online","only","open","opera","opinion","oppose","option","orange","orbit","orchard","order","ordinary","organ","orient","original","orphan","ostrich","other","outdoor","outer","output","outside","oval","oven","over","own","owner","oxygen","oyster","ozone","pact","paddle","page","pair","palace","palm","panda","panel","panic","panther","paper","parade","parent","park","parrot","party","pass","patch","path","patient","patrol","pattern","pause","pave","payment","peace","peanut","pear","peasant","pelican","pen","penalty","pencil","people","pepper","perfect","permit","person","pet","phone","photo","phrase","physical","piano","picnic","picture","piece","pig","pigeon","pill","pilot","pink","pioneer","pipe","pistol","pitch","pizza","place","planet","plastic","plate","play","please","pledge","pluck","plug","plunge","poem","poet","point","polar","pole","police","pond","pony","pool","popular","portion","position","possible","post","potato","pottery","poverty","powder","power","practice","praise","predict","prefer","prepare","present","pretty","prevent","price","pride","primary","print","priority","prison","private","prize","problem","process","produce","profit","program","project","promote","proof","property","prosper","protect","proud","provide","public","pudding","pull","pulp","pulse","pumpkin","punch","pupil","puppy","purchase","purity","purpose","purse","push","put","puzzle","pyramid","quality","quantum","quarter","question","quick","quit","quiz","quote","rabbit","raccoon","race","rack","radar","radio","rail","rain","raise","rally","ramp","ranch","random","range","rapid","rare","rate","rather","raven","raw","razor","ready","real","reason","rebel","rebuild","recall","receive","recipe","record","recycle","reduce","reflect","reform","refuse","region","regret","regular","reject","relax","release","relief","rely","remain","remember","remind","remove","render","renew","rent","reopen","repair","repeat","replace","report","require","rescue","resemble","resist","resource","response","result","retire","retreat","return","reunion","reveal","review","reward","rhythm","rib","ribbon","rice","rich","ride","ridge","rifle","right","rigid","ring","riot","ripple","risk","ritual","rival","river","road","roast","robot","robust","rocket","romance","roof","rookie","room","rose","rotate","rough","round","route","royal","rubber","rude","rug","rule","run","runway","rural","sad","saddle","sadness","safe","sail","salad","salmon","salon","salt","salute","same","sample","sand","satisfy","satoshi","sauce","sausage","save","say","scale","scan","scare","scatter","scene","scheme","school","science","scissors","scorpion","scout","scrap","screen","script","scrub","sea","search","season","seat","second","secret","section","security","seed","seek","segment","select","sell","seminar","senior","sense","sentence","series","service","session","settle","setup","seven","shadow","shaft","shallow","share","shed","shell","sheriff","shield","shift","shine","ship","shiver","shock","shoe","shoot","shop","short","shoulder","shove","shrimp","shrug","shuffle","shy","sibling","sick","side","siege","sight","sign","silent","silk","silly","silver","similar","simple","since","sing","siren","sister","situate","six","size","skate","sketch","ski","skill","skin","skirt","skull","slab","slam","sleep","slender","slice","slide","slight","slim","slogan","slot","slow","slush","small","smart","smile","smoke","smooth","snack","snake","snap","sniff","snow","soap","soccer","social","sock","soda","soft","solar","soldier","solid","solution","solve","someone","song","soon","sorry","sort","soul","sound","soup","source","south","space","spare","spatial","spawn","speak","special","speed","spell","spend","sphere","spice","spider","spike","spin","spirit","split","spoil","sponsor","spoon","sport","spot","spray","spread","spring","spy","square","squeeze","squirrel","stable","stadium","staff","stage","stairs","stamp","stand","start","state","stay","steak","steel","stem","step","stereo","stick","still","sting","stock","stomach","stone","stool","story","stove","strategy","street","strike","strong","struggle","student","stuff","stumble","style","subject","submit","subway","success","such","sudden","suffer","sugar","suggest","suit","summer","sun","sunny","sunset","super","supply","supreme","sure","surface","surge","surprise","surround","survey","suspect","sustain","swallow","swamp","swap","swarm","swear","sweet","swift","swim","swing","switch","sword","symbol","symptom","syrup","system","table","tackle","tag","tail","talent","talk","tank","tape","target","task","taste","tattoo","taxi","teach","team","tell","ten","tenant","tennis","tent","term","test","text","thank","that","theme","then","theory","there","they","thing","this","thought","three","thrive","throw","thumb","thunder","ticket","tide","tiger","tilt","timber","time","tiny","tip","tired","tissue","title","toast","tobacco","today","toddler","toe","together","toilet","token","tomato","tomorrow","tone","tongue","tonight","tool","tooth","top","topic","topple","torch","tornado","tortoise","toss","total","tourist","toward","tower","town","toy","track","trade","traffic","tragic","train","transfer","trap","trash","travel","tray","treat","tree","trend","trial","tribe","trick","trigger","trim","trip","trophy","trouble","truck","true","truly","trumpet","trust","truth","try","tube","tuition","tumble","tuna","tunnel","turkey","turn","turtle","twelve","twenty","twice","twin","twist","two","type","typical","ugly","umbrella","unable","unaware","uncle","uncover","under","undo","unfair","unfold","unhappy","uniform","unique","unit","universe","unknown","unlock","until","unusual","unveil","update","upgrade","uphold","upon","upper","upset","urban","urge","usage","use","used","useful","useless","usual","utility","vacant","vacuum","vague","valid","valley","valve","van","vanish","vapor","various","vast","vault","vehicle","velvet","vendor","venture","venue","verb","verify","version","very","vessel","veteran","viable","vibrant","vicious","victory","video","view","village","vintage","violin","virtual","virus","visa","visit","visual","vital","vivid","vocal","voice","void","volcano","volume","vote","voyage","wage","wagon","wait","walk","wall","walnut","want","warfare","warm","warrior","wash","wasp","waste","water","wave","way","wealth","weapon","wear","weasel","weather","web","wedding","weekend","weird","welcome","west","wet","whale","what","wheat","wheel","when","where","whip","whisper","wide","width","wife","wild","will","win","window","wine","wing","wink","winner","winter","wire","wisdom","wise","wish","witness","wolf","woman","wonder","wood","wool","word","work","world","worry","worth","wrap","wreck","wrestle","wrist","write","wrong","yard","year","yellow","you","young","youth","zebra","zero","zone","zoo"];

// Copyright (C) 2022 Deliberative Technologies P.C.
const randomBytesMemory = (bytes) => {
    const memoryLen = bytes * Uint8Array.BYTES_PER_ELEMENT;
    const pages = memoryLenToPages(memoryLen);
    return new WebAssembly.Memory({ initial: pages, maximum: pages });
};
const randomNumberInRangeMemory = (min, max) => {
    const bytesNeeded = Math.ceil(Math.log2(max - min) / 8);
    const memoryLen = bytesNeeded * Uint8Array.BYTES_PER_ELEMENT;
    const pages = memoryLenToPages(memoryLen);
    return new WebAssembly.Memory({ initial: pages, maximum: pages });
};
var memory$2 = { randomBytesMemory, randomNumberInRangeMemory };

// Copyright (C) 2022 Deliberative Technologies P.C.
const randomBytes = async (n, module) => {
    const wasmMemory = module
        ? module.wasmMemory
        : memory$2.randomBytesMemory(n);
    const bytes = new Uint8Array(wasmMemory.buffer, 0, n);
    const libsodiumModule = module ||
        (await libsodiumMethodsModule({
            wasmMemory,
        }));
    const result = libsodiumModule._random_bytes(n, bytes.byteOffset);
    if (result === 0)
        return new Uint8Array([...bytes]);
    throw new Error("Could not generate random data");
};

// Copyright (C) 2022 Deliberative Technologies P.C.
const sha512Memory = (arrayLen) => {
    const memoryLen = (arrayLen + crypto_hash_sha512_BYTES) * Uint8Array.BYTES_PER_ELEMENT;
    const pages = memoryLenToPages(memoryLen);
    return new WebAssembly.Memory({ initial: pages, maximum: pages });
};
const merkleRootMemory = (maxDataLen) => {
    const initialMemoryLen = (maxDataLen + crypto_hash_sha512_BYTES) * Uint8Array.BYTES_PER_ELEMENT;
    const initialMemoryPages = memoryLenToPages(initialMemoryLen);
    const subsequentMemoryLen = 3 * crypto_hash_sha512_BYTES * Uint8Array.BYTES_PER_ELEMENT;
    const subsequentMemoryPages = memoryLenToPages(subsequentMemoryLen);
    return {
        initialMemory: new WebAssembly.Memory({
            initial: initialMemoryPages,
            maximum: initialMemoryPages,
        }),
        subsequentMemory: new WebAssembly.Memory({
            initial: subsequentMemoryPages,
            maximum: subsequentMemoryPages,
        }),
    };
};
var memory$1 = {
    sha512Memory,
    merkleRootMemory,
};

// Copyright (C) 2022 Deliberative Technologies P.C.
const sha512 = async (data, module) => {
    const dataLen = data.length;
    const wasmMemory = module
        ? module.wasmMemory
        : memory$1.sha512Memory(dataLen);
    let offset = 0;
    const arr = new Uint8Array(wasmMemory.buffer, offset, dataLen);
    arr.set([...data]);
    offset += dataLen;
    const hash = new Uint8Array(wasmMemory.buffer, offset, crypto_hash_sha512_BYTES);
    const libsodiumModule = module || (await libsodiumMethodsModule({ wasmMemory }));
    const result = libsodiumModule._sha512(dataLen, arr.byteOffset, hash.byteOffset);
    if (result === 0)
        return new Uint8Array([...hash]);
    throw new Error("Could not hash the array.");
};

// Copyright (C) 2022 Deliberative Technologies P.C.
/**
 * Generates a sequence of words that represents a random seed that
 * can be translated into a cryptographic keypair.
 */
const generateMnemonic = async (strength) => {
    strength = strength || 128;
    if (strength % 32 !== 0) {
        throw new TypeError("Mnemonic strength needs to be multiple of 32.");
    }
    if (!wordlist) {
        throw new Error("English wordlist could not be loaded.");
    }
    const entropy = await randomBytes(strength / 8);
    // 128 <= ENT <= 256
    if (entropy.length < 16) {
        throw new TypeError("Entropy length too small.");
    }
    if (entropy.length > 32) {
        throw new TypeError("Entropy length too large.");
    }
    if (entropy.length % 4 !== 0) {
        throw new TypeError("Entropy length is not multiple of 4.");
    }
    const entropyBits = entropy.reduce((str, byte) => str + byte.toString(2).padStart(8, "0"), "");
    const CS = strength / 32;
    const entropyHash = await sha512(entropy);
    const checksumBits = entropyHash
        .reduce((str, byte) => str + byte.toString(2).padStart(8, "0"), "")
        .slice(0, CS);
    const bits = entropyBits + checksumBits;
    const chunks = bits.match(/(.{1,11})/g);
    if (!chunks)
        throw new Error("Did not find enough 1s and 11s in binary format.");
    const words = chunks.map((binary) => {
        const index = parseInt(binary, 2);
        return wordlist[index];
    });
    return words.join(" ");
};

// Copyright (C) 2022 Deliberative Technologies P.C.
const normalize$1 = (str) => {
    return (str || "").normalize("NFKD");
};
const mnemonicToEntropy = async (mnemonic) => {
    if (!wordlist) {
        throw new Error("Could not load english wordlist");
    }
    const words = normalize$1(mnemonic).split(" ");
    if (words.length % 3 !== 0) {
        throw new Error("Number of words in mnemonic must be multiple of three.");
    }
    // convert word indices to 11 bit binary strings
    const bits = words
        .map((word) => {
        const index = wordlist.indexOf(word);
        if (index === -1) {
            throw new Error("Could not find word in wordlist.");
        }
        return index.toString(2).padStart(11, "0");
        // return lpad(index.toString(2), "0", 11);
    })
        .join("");
    // split the binary string into ENT/CS
    const dividerIndex = Math.floor(bits.length / 33) * 32;
    const entropyBits = bits.slice(0, dividerIndex);
    const checksumBits = bits.slice(dividerIndex);
    // convert bits to entropy
    const entropyBitsMatched = entropyBits.match(/(.{1,8})/g);
    if (!entropyBitsMatched)
        throw new Error("Invalid entropy bits.");
    // calculate the checksum and compare
    const entropy = entropyBitsMatched.map((bin) => parseInt(bin, 2));
    if (entropy.length < 16) {
        throw new Error("Entropy length too small (less than 128 bits).");
    }
    if (entropy.length > 32) {
        throw new Error("Entropy length too large (more than 256 bits).");
    }
    if (entropy.length % 4 !== 0) {
        throw new Error("Entropy length must be a multiple of 4.");
    }
    const CS = entropy.length / 4;
    const entropyHash = await sha512(Uint8Array.from([...entropy]));
    const newChecksum = entropyHash
        .reduce((str, byte) => str + byte.toString(2).padStart(8, "0"), "")
        .slice(0, CS);
    if (newChecksum !== checksumBits) {
        throw new Error("Invalid checksum.");
    }
    return true;
};
const validateMnemonic = async (mnemonic) => {
    try {
        return await mnemonicToEntropy(mnemonic);
    }
    catch (e) {
        return false;
    }
};

// Copyright (C) 2022 Deliberative Technologies P.C.
const argon2Memory = (mnemonicLen) => {
    const memoryLen = (75 * 1024 * 1024 +
        mnemonicLen +
        crypto_sign_ed25519_SEEDBYTES +
        crypto_pwhash_argon2id_SALTBYTES) *
        Uint8Array.BYTES_PER_ELEMENT;
    const pages = memoryLenToPages(memoryLen);
    return new WebAssembly.Memory({ initial: pages, maximum: pages });
};
var mnemonicMemory = {
    argon2Memory,
};

// Copyright (C) 2022 Deliberative Technologies P.C.
const normalize = (str) => {
    return (str || "").normalize("NFKD");
};
const argon2 = async (mnemonic, module) => {
    const mnemonicNormalized = normalize(mnemonic);
    const mnemonicBuffer = Buffer.from(mnemonicNormalized, "utf8");
    const mnemonicInt8Array = Int8Array.from(mnemonicBuffer);
    const mnemonicArrayLen = mnemonicInt8Array.length;
    const saltUint8Array = await randomBytes(crypto_pwhash_argon2id_SALTBYTES);
    const wasmMemory = module
        ? module.wasmMemory
        : mnemonicMemory.argon2Memory(mnemonicArrayLen);
    let offset = 0;
    const seed = new Uint8Array(wasmMemory.buffer, offset, crypto_sign_ed25519_SEEDBYTES);
    offset += crypto_sign_ed25519_SEEDBYTES;
    const mnmnc = new Int8Array(wasmMemory.buffer, offset, mnemonicArrayLen);
    mnmnc.set([...mnemonicInt8Array]);
    offset += mnemonicArrayLen;
    const salt = new Uint8Array(wasmMemory.buffer, offset, crypto_pwhash_argon2id_SALTBYTES);
    salt.set([...saltUint8Array]);
    const libsodiumModule = module || (await libsodiumMethodsModule({ wasmMemory }));
    const result = libsodiumModule._argon2(mnemonicArrayLen, seed.byteOffset, mnmnc.byteOffset, salt.byteOffset);
    if (result === 0) {
        return new Uint8Array([...seed]);
    }
    else {
        throw new Error("Could not generate argon2id for mnemonic.");
    }
};

// Copyright (C) 2022 Deliberative Technologies P.C.
const keyPairFromMnemonic = async (mnemonic) => {
    const isValid = await validateMnemonic(mnemonic);
    if (!isValid)
        throw new Error("Invalid mnemonic.");
    const seed = await argon2(mnemonic);
    // const privateKeySeed = new Uint8Array(seed.toJSON().data.slice(0, 32));
    const keypair = await keyPair.keyPairFromSeed(seed);
    if (!keypair)
        throw new Error("Invalid seed from mnemonic.");
    return keypair;
};

// Copyright (C) 2022 Deliberative Technologies P.C.
var mnemonic = {
    generateMnemonic,
    validateMnemonic,
    keyPairFromMnemonic,
};

// Copyright (C) 2022 Deliberative Technologies P.C.
const getMerkleRoot = async (tree) => {
    const treeLength = tree.length;
    const lengths = tree.map((a) => a.length);
    const maxDataLen = lengths.indexOf(Math.max(...lengths));
    const { initialMemory, subsequentMemory } = memory$1.merkleRootMemory(maxDataLen);
    const libsodiumInitialModule = await libsodiumMethodsModule({
        wasmMemory: initialMemory,
    });
    const libsodiumSubsequentModule = await libsodiumMethodsModule({
        wasmMemory: subsequentMemory,
    });
    const hashes = [];
    const concatHashes = new Uint8Array(2 * crypto_hash_sha512_BYTES);
    let leaves = treeLength;
    let oddLeaves;
    while (leaves > 1) {
        oddLeaves = leaves % 2 !== 0;
        let i = 0;
        if (leaves === treeLength) {
            do {
                const hash = await sha512(tree[i++], libsodiumInitialModule);
                hashes.push(hash);
            } while (i < leaves);
        }
        i = 0;
        do {
            if (oddLeaves && i === leaves - 1) {
                concatHashes.set([...hashes[i * 2], ...hashes[i * 2]]);
            }
            else {
                concatHashes.set([...hashes[i * 2], ...hashes[i * 2 + 1]]);
            }
            const hash = await sha512(concatHashes, libsodiumSubsequentModule);
            hashes[i++].set([...hash]);
        } while (i * 2 + 1 < leaves);
        hashes.length = Math.ceil(hashes.length / 2);
        leaves = hashes.length;
    }
    if (hashes.length === 1) {
        return hashes[0];
    }
    else {
        throw new Error("Something went wrong");
    }
};

// Copyright (C) 2022 Deliberative Technologies P.C.
var hash = {
    sha512,
    getMerkleRoot,
    memory: memory$1,
};

// Copyright (C) 2022 Deliberative Technologies P.C.
const LOG_AND_EXP = 256 + 510;
const splitSecretMemory = (secretLen, sharesLen, threshold) => {
    const memoryLen = (sharesLen * (secretLen + 1) * (LOG_AND_EXP + 1) + secretLen + threshold) *
        Uint8Array.BYTES_PER_ELEMENT;
    const pages = memoryLenToPages(memoryLen);
    return new WebAssembly.Memory({ initial: pages, maximum: pages });
};
const restoreSecretMemory = (secretLen, sharesLen) => {
    const memoryLen = (sharesLen * (secretLen + 1) * (LOG_AND_EXP + 1) +
        secretLen +
        2 * sharesLen) *
        Uint8Array.BYTES_PER_ELEMENT;
    const pages = memoryLenToPages(memoryLen);
    return new WebAssembly.Memory({ initial: pages, maximum: pages });
};
var memory = { splitSecretMemory, restoreSecretMemory };

var shamirMethodsModule = (() => {
  var _scriptDir = typeof document !== 'undefined' && document.currentScript ? document.currentScript.src : undefined;
  if (typeof __filename !== 'undefined') _scriptDir = _scriptDir || __filename;
  return (
function(shamirMethodsModule) {
  shamirMethodsModule = shamirMethodsModule || {};
var g;g||(g=typeof shamirMethodsModule !== 'undefined' ? shamirMethodsModule : {});var aa,ba;g.ready=new Promise(function(a,b){aa=a;ba=b;});var ca=Object.assign({},g),da=[],ea="./this.program",k=(a,b)=>{throw b;},fa="object"==typeof window,l="function"==typeof importScripts,t="object"==typeof process&&"object"==typeof process.versions&&"string"==typeof process.versions.node,u="",ha,v,w,fs,x,ia;
if(t)u=l?require("path").dirname(u)+"/":__dirname+"/",ia=()=>{x||(fs=require("fs"),x=require("path"));},ha=function(a,b){ia();a=x.normalize(a);return fs.readFileSync(a,b?void 0:"utf8")},w=a=>{a=ha(a,!0);a.buffer||(a=new Uint8Array(a));return a},v=(a,b,c)=>{ia();a=x.normalize(a);fs.readFile(a,function(d,e){d?c(d):b(e.buffer);});},1<process.argv.length&&(ea=process.argv[1].replace(/\\/g,"/")),da=process.argv.slice(2),k=(a,b)=>{if(noExitRuntime)throw process.exitCode=a,b;b instanceof ja||y("exiting due to exception: "+
b);process.exit(a);},g.inspect=function(){return "[Emscripten Module object]"};else if(fa||l)l?u=self.location.href:"undefined"!=typeof document&&document.currentScript&&(u=document.currentScript.src),_scriptDir&&(u=_scriptDir),0!==u.indexOf("blob:")?u=u.substr(0,u.replace(/[?#].*/,"").lastIndexOf("/")+1):u="",ha=a=>{var b=new XMLHttpRequest;b.open("GET",a,!1);b.send(null);return b.responseText},l&&(w=a=>{var b=new XMLHttpRequest;b.open("GET",a,!1);b.responseType="arraybuffer";b.send(null);return new Uint8Array(b.response)}),
v=(a,b,c)=>{var d=new XMLHttpRequest;d.open("GET",a,!0);d.responseType="arraybuffer";d.onload=()=>{200==d.status||0==d.status&&d.response?b(d.response):c();};d.onerror=c;d.send(null);};var ka=g.print||console.log.bind(console),y=g.printErr||console.warn.bind(console);Object.assign(g,ca);ca=null;g.arguments&&(da=g.arguments);g.thisProgram&&(ea=g.thisProgram);g.quit&&(k=g.quit);var z=g.dynamicLibraries||[],A;g.wasmBinary&&(A=g.wasmBinary);var noExitRuntime=g.noExitRuntime||!0;
"object"!=typeof WebAssembly&&B("no native wasm support detected");var D,la=!1,ma="undefined"!=typeof TextDecoder?new TextDecoder("utf8"):void 0;
function E(a,b,c){var d=b+c;for(c=b;a[c]&&!(c>=d);)++c;if(16<c-b&&a.buffer&&ma)return ma.decode(a.subarray(b,c));for(d="";b<c;){var e=a[b++];if(e&128){var f=a[b++]&63;if(192==(e&224))d+=String.fromCharCode((e&31)<<6|f);else {var h=a[b++]&63;e=224==(e&240)?(e&15)<<12|f<<6|h:(e&7)<<18|f<<12|h<<6|a[b++]&63;65536>e?d+=String.fromCharCode(e):(e-=65536,d+=String.fromCharCode(55296|e>>10,56320|e&1023));}}else d+=String.fromCharCode(e);}return d}
function na(a,b,c,d){if(!(0<d))return 0;var e=c;d=c+d-1;for(var f=0;f<a.length;++f){var h=a.charCodeAt(f);if(55296<=h&&57343>=h){var m=a.charCodeAt(++f);h=65536+((h&1023)<<10)|m&1023;}if(127>=h){if(c>=d)break;b[c++]=h;}else {if(2047>=h){if(c+1>=d)break;b[c++]=192|h>>6;}else {if(65535>=h){if(c+2>=d)break;b[c++]=224|h>>12;}else {if(c+3>=d)break;b[c++]=240|h>>18;b[c++]=128|h>>12&63;}b[c++]=128|h>>6&63;}b[c++]=128|h&63;}}b[c]=0;return c-e}
function oa(a){for(var b=0,c=0;c<a.length;++c){var d=a.charCodeAt(c);127>=d?b++:2047>=d?b+=2:55296<=d&&57343>=d?(b+=4,++c):b+=3;}return b}var F,G,pa,H,qa;function ra(a){F=a;g.HEAP8=G=new Int8Array(a);g.HEAP16=new Int16Array(a);g.HEAP32=H=new Int32Array(a);g.HEAPU8=pa=new Uint8Array(a);g.HEAPU16=new Uint16Array(a);g.HEAPU32=new Uint32Array(a);g.HEAPF32=new Float32Array(a);g.HEAPF64=qa=new Float64Array(a);}var sa=g.INITIAL_MEMORY||2097152;
g.wasmMemory?D=g.wasmMemory:D=new WebAssembly.Memory({initial:sa/65536,maximum:1600});D&&(F=D.buffer);sa=F.byteLength;ra(F);var I=new WebAssembly.Table({initial:5,element:"anyfunc"}),ta=[],ua=[],va=[],xa=[],ya=[],J=!1;function za(){var a=g.preRun.shift();ta.unshift(a);}var K=0,L=null;function Ba(){K++;g.monitorRunDependencies&&g.monitorRunDependencies(K);}
function Ca(){K--;g.monitorRunDependencies&&g.monitorRunDependencies(K);if(0==K&&(L)){var a=L;L=null;a();}}function B(a){if(g.onAbort)g.onAbort(a);a="Aborted("+a+")";y(a);la=!0;a=new WebAssembly.RuntimeError(a+". Build with -sASSERTIONS for more info.");ba(a);throw a;}function Da(){return M.startsWith("data:application/octet-stream;base64,")}var M;M="shamirMethodsModule.wasm";if(!Da()){var Ea=M;M=g.locateFile?g.locateFile(Ea,u):u+Ea;}
function Fa(){var a=M;try{if(a==M&&A)return new Uint8Array(A);if(w)return w(a);throw "both async and sync fetching of the wasm failed";}catch(b){B(b);}}
function Ga(){if(!A&&(fa||l)){if("function"==typeof fetch&&!M.startsWith("file://"))return fetch(M,{credentials:"same-origin"}).then(function(a){if(!a.ok)throw "failed to load wasm binary file at '"+M+"'";return a.arrayBuffer()}).catch(function(){return Fa()});if(v)return new Promise(function(a,b){v(M,function(c){a(new Uint8Array(c));},b);})}return Promise.resolve().then(function(){return Fa()})}
var Ha={776:()=>g.J(),812:()=>{if(void 0===g.J)try{var a="object"===typeof window?window:self,b="undefined"!==typeof a.crypto?a.crypto:a.msCrypto;a=function(){var d=new Uint32Array(1);b.getRandomValues(d);return d[0]>>>0};a();g.J=a;}catch(d){try{var c=require("crypto");a=function(){var e=c.randomBytes(4);return (e[0]<<24|e[1]<<16|e[2]<<8|e[3])>>>0};a();g.J=a;}catch(e){throw "No secure random number generator found";}}}};
function ja(a){this.name="ExitStatus";this.message="Program terminated with exit("+a+")";this.status=a;}var N={},Ia=new Set([]),O={get:function(a,b){(a=N[b])||(a=N[b]=new WebAssembly.Global({value:"i32",mutable:!0}));Ia.has(b)||(a.required=!0);return a}};function P(a){for(;0<a.length;)a.shift()(g);}
function Ja(a){function b(){for(var n=0,r=1;;){var C=a[e++];n+=(C&127)*r;r*=128;if(!(C&128))break}return n}function c(){var n=b();e+=n;return E(a,e-n,n)}function d(n,r){if(n)throw Error(r);}var e=0,f=0,h="dylink.0";a instanceof WebAssembly.Module?(f=WebAssembly.Module.customSections(a,h),0===f.length&&(h="dylink",f=WebAssembly.Module.customSections(a,h)),d(0===f.length,"need dylink section"),a=new Uint8Array(f[0]),f=a.length):(f=1836278016==(new Uint32Array((new Uint8Array(a.subarray(0,24))).buffer))[0],
d(!f,"need to see wasm magic number"),d(0!==a[8],"need the dylink section to be first"),e=9,f=b(),f=e+f,h=c());var m={B:[],ia:new Set,aa:new Set};if("dylink"==h){m.K=b();m.W=b();m.I=b();m.ha=b();h=b();for(var p=0;p<h;++p){var q=c();m.B.push(q);}}else for(d("dylink.0"!==h);e<f;)if(h=a[e++],p=b(),1===h)m.K=b(),m.W=b(),m.I=b(),m.ha=b();else if(2===h)for(h=b(),p=0;p<h;++p)q=c(),m.B.push(q);else if(3===h)for(h=b();h--;)p=c(),q=b(),q&256&&m.ia.add(p);else if(4===h)for(h=b();h--;)c(),p=c(),q=b(),1==(q&3)&&
m.aa.add(p);else e+=p;return m}function Ka(a){var b=["stackAlloc","stackSave","stackRestore"];return 0==a.indexOf("dynCall_")||b.includes(a)?a:"_"+a}function La(a){for(var b in a)if(a.hasOwnProperty(b)){Q.hasOwnProperty(b)||(Q[b]=a[b]);var c=Ka(b);g.hasOwnProperty(c)||(g[c]=a[b]);"__main_argc_argv"==b&&(g._main=a[b]);}}var Ma={},R=[];function Na(a){var b=R[a];b||(a>=R.length&&(R.length=a+1),R[a]=b=I.get(a));return b}
function Oa(a){return function(){var b=Pa();try{var c=arguments[0],d=Array.prototype.slice.call(arguments,1);if(a.includes("j")){var e=g["dynCall_"+a];var f=d&&d.length?e.apply(null,[c].concat(d)):e.call(null,c);}else f=Na(c).apply(null,d);return f}catch(h){Qa(b);if(h!==h+0)throw h;Ra(1,0);}}}var Sa=1051680;function Ta(a){if(J)return Ua(a);var b=Sa;Sa=a=b+a+15&-16;N.__heap_base.value=a;return b}function Va(a,b){if(S)for(var c=a;c<a+b;c++){var d=Na(c);d&&S.set(d,c);}}var S=void 0,Wa=[];
function Xa(a,b){S||(S=new WeakMap,Va(0,I.length));if(S.has(a))return S.get(a);if(Wa.length)var c=Wa.pop();else {try{I.grow(1);}catch(m){if(!(m instanceof RangeError))throw m;throw "Unable to grow wasm table. Set ALLOW_TABLE_GROWTH.";}c=I.length-1;}try{var d=c;I.set(d,a);R[d]=I.get(d);}catch(m){if(!(m instanceof TypeError))throw m;if("function"==typeof WebAssembly.Function){d=WebAssembly.Function;for(var e={i:"i32",j:"i64",f:"f32",d:"f64",p:"i32"},f={parameters:[],results:"v"==b[0]?[]:[e[b[0]]]},h=1;h<
b.length;++h)f.parameters.push(e[b[h]]);d=new d(f,a);}else {d=[1,96];e=b.slice(0,1);b=b.slice(1);f={i:127,p:127,j:126,f:125,d:124};h=b.length;128>h?d.push(h):d.push(h%128|128,h>>7);for(h=0;h<b.length;++h)d.push(f[b[h]]);"v"==e?d.push(0):d.push(1,f[e]);b=[0,97,115,109,1,0,0,0,1];e=d.length;128>e?b.push(e):b.push(e%128|128,e>>7);b.push.apply(b,d);b.push(2,7,1,1,101,1,102,0,0,7,5,1,1,102,0,0);d=new WebAssembly.Module(new Uint8Array(b));d=(new WebAssembly.Instance(d,{e:{f:a}})).exports.f;}b=c;I.set(b,d);
R[b]=I.get(b);}S.set(a,c);return c}
function Ya(a,b){var c={},d;for(d in a){var e=a[d];"object"==typeof e&&(e=e.value);"number"==typeof e&&(e+=b);c[d]=e;}a=void 0;for(var f in c)!"__cpp_exception __c_longjmp __wasm_apply_data_relocs __dso_handle __tls_size __tls_align __set_stack_limits _emscripten_tls_init __wasm_init_tls __wasm_call_ctors".split(" ").includes(f)&&(b=c[f],f.startsWith("orig$")&&(f=f.split("$")[1],a=!0),N[f]||(N[f]=new WebAssembly.Global({value:"i32",mutable:!0})),a||0==N[f].value)&&("function"==typeof b?N[f].value=
Xa(b):"number"==typeof b?N[f].value=b:"bigint"==typeof b?N[f].value=Number(b):y("unhandled export type for `"+f+"`: "+typeof b));return c}function Za(a,b){var c;b&&(c=Q["orig$"+a]);c||(c=Q[a])&&c.oa&&(c=void 0);c||(c=g[Ka(a)]);!c&&a.startsWith("invoke_")&&(c=Oa(a.split("_")[1]));return c}function $a(a,b){return Math.ceil(a/b)*b}
function ab(a,b){function c(){function e(n){Va(m,d.I);p=Ya(n.exports,h);b.ba||bb();(n=p.__wasm_call_ctors)&&(J?n():ua.push(n));(n=p.__wasm_apply_data_relocs)&&(J?n():ya.push(n));return p}var f=Math.pow(2,d.W);f=Math.max(f,16);var h=d.K?$a(Ta(d.K+f),f):0,m=d.I?I.length:0;f=m+d.I-I.length;0<f&&I.grow(f);var p;f=new Proxy({},{get:function(n,r){switch(r){case "__memory_base":return h;case "__table_base":return m}if(r in Q)return Q[r];if(!(r in n)){var C;n[r]=function(){if(!C){var wa=Za(r,!1);wa||(wa=
p[r]);C=wa;}return C.apply(null,arguments)};}return n[r]}});f={"GOT.mem":new Proxy({},O),"GOT.func":new Proxy({},O),env:f,qa:f};if(b.A)return a instanceof WebAssembly.Module?(f=new WebAssembly.Instance(a,f),Promise.resolve(e(f))):WebAssembly.instantiate(a,f).then(function(n){return e(n.instance)});var q=a instanceof WebAssembly.Module?a:new WebAssembly.Module(a);f=new WebAssembly.Instance(q,f);return e(f)}var d=Ja(a);Ia=d.aa;if(b.A)return d.B.reduce(function(e,f){return e.then(function(){return cb(f,
b)})},Promise.resolve()).then(function(){return c()});d.B.forEach(function(e){cb(e,b);});return c()}
function cb(a,b){function c(h){if(b.fs&&b.fs.ka(h)){var m=b.fs.readFile(h,{encoding:"binary"});m instanceof Uint8Array||(m=new Uint8Array(m));return b.A?Promise.resolve(m):m}if(b.A)return new Promise(function(p,q){v(h,n=>p(new Uint8Array(n)),q);});if(!w)throw Error(h+": file not found, and synchronous loading of external files is not available");return w(h)}function d(){if("undefined"!=typeof preloadedWasm&&preloadedWasm[a]){var h=preloadedWasm[a];return b.A?Promise.resolve(h):h}return b.A?c(a).then(function(m){return ab(m,
b)}):ab(c(a),b)}function e(h){f.global&&La(h);f.module=h;}b=b||{global:!0,L:!0};var f=Ma[a];if(f)return b.global&&!f.global&&(f.global=!0,"loading"!==f.module&&La(f.module)),b.L&&Infinity!==f.O&&(f.O=Infinity),f.O++,b.A?Promise.resolve(!0):!0;f={O:b.L?Infinity:1,name:a,module:"loading",global:b.global};Ma[a]=f;if(b.A)return d().then(function(h){e(h);return !0});e(d());return !0}
function bb(){for(var a in N)if(0==N[a].value){var b=Za(a,!0);if(b||N[a].required)if("function"==typeof b)N[a].value=Xa(b,b.$);else if("number"==typeof b)N[a].value=b;else throw Error("bad export type for `"+a+"`: "+typeof b);}}function db(){z.length?(Ba(),z.reduce(function(a,b){return a.then(function(){return cb(b,{A:!0,global:!0,L:!0,ba:!0})})},Promise.resolve()).then(function(){bb();Ca();})):bb();}
var eb=new WebAssembly.Global({value:"i32",mutable:!1},1024),fb=new WebAssembly.Global({value:"i32",mutable:!0},1051680),gb=new WebAssembly.Global({value:"i32",mutable:!1},1),hb=[];function ib(a,b,c){a-=1024;hb.length=0;var d;for(c>>=2;d=pa[b++];)c+=105!=d&c,hb.push(105==d?H[c]:qa[c++>>1]),++c;return Ha[a].apply(null,hb)}ib.$="ippp";
function jb(a){var b=pa.length;a>>>=0;if(104857600<a)return !1;for(var c=1;4>=c;c*=2){var d=b*(1+.2/c);d=Math.min(d,a+100663296);var e=Math;d=Math.max(a,d);e=e.min.call(e,104857600,d+(65536-d%65536)%65536);a:{try{D.grow(e-F.byteLength+65535>>>16);ra(D.buffer);var f=1;break a}catch(h){}f=void 0;}if(f)return !0}return !1}jb.$="ip";
var kb=(a,b)=>{for(var c=0,d=a.length-1;0<=d;d--){var e=a[d];"."===e?a.splice(d,1):".."===e?(a.splice(d,1),c++):c&&(a.splice(d,1),c--);}if(b)for(;c;c--)a.unshift("..");return a},lb=a=>{var b="/"===a.charAt(0),c="/"===a.substr(-1);(a=kb(a.split("/").filter(d=>!!d),!b).join("/"))||b||(a=".");a&&c&&(a+="/");return (b?"/":"")+a},mb=a=>{var b=/^(\/?|)([\s\S]*?)((?:\.{1,2}|[^\/]+?|)(\.[^.\/]*|))(?:[\/]*)$/.exec(a).slice(1);a=b[0];b=b[1];if(!a&&!b)return ".";b&&(b=b.substr(0,b.length-1));return a+b},nb=a=>
{if("/"===a)return "/";a=lb(a);a=a.replace(/\/$/,"");var b=a.lastIndexOf("/");return -1===b?a:a.substr(b+1)};function ob(){if("object"==typeof crypto&&"function"==typeof crypto.getRandomValues){var a=new Uint8Array(1);return ()=>{crypto.getRandomValues(a);return a[0]}}if(t)try{var b=require("crypto");return ()=>b.randomBytes(1)[0]}catch(c){}return ()=>B("randomDevice")}
function pb(){for(var a="",b=!1,c=arguments.length-1;-1<=c&&!b;c--){b=0<=c?arguments[c]:"/";if("string"!=typeof b)throw new TypeError("Arguments to path.resolve must be strings");if(!b)return "";a=b+"/"+a;b="/"===b.charAt(0);}a=kb(a.split("/").filter(d=>!!d),!b).join("/");return (b?"/":"")+a||"."}var qb=[];function rb(a,b){qb[a]={input:[],output:[],C:b};sb(a,tb);}
var tb={open:function(a){var b=qb[a.node.rdev];if(!b)throw new T(43);a.tty=b;a.seekable=!1;},close:function(a){a.tty.C.flush(a.tty);},flush:function(a){a.tty.C.flush(a.tty);},read:function(a,b,c,d){if(!a.tty||!a.tty.C.V)throw new T(60);for(var e=0,f=0;f<d;f++){try{var h=a.tty.C.V(a.tty);}catch(m){throw new T(29);}if(void 0===h&&0===e)throw new T(6);if(null===h||void 0===h)break;e++;b[c+f]=h;}e&&(a.node.timestamp=Date.now());return e},write:function(a,b,c,d){if(!a.tty||!a.tty.C.M)throw new T(60);try{for(var e=
0;e<d;e++)a.tty.C.M(a.tty,b[c+e]);}catch(f){throw new T(29);}d&&(a.node.timestamp=Date.now());return e}},ub={V:function(a){if(!a.input.length){var b=null;if(t){var c=Buffer.alloc(256),d=0;try{d=fs.readSync(process.stdin.fd,c,0,256,-1);}catch(e){if(e.toString().includes("EOF"))d=0;else throw e;}0<d?b=c.slice(0,d).toString("utf-8"):b=null;}else "undefined"!=typeof window&&"function"==typeof window.prompt?(b=window.prompt("Input: "),null!==b&&(b+="\n")):"function"==typeof readline&&(b=readline(),null!==
b&&(b+="\n"));if(!b)return null;c=Array(oa(b)+1);b=na(b,c,0,c.length);c.length=b;a.input=c;}return a.input.shift()},M:function(a,b){null===b||10===b?(ka(E(a.output,0)),a.output=[]):0!=b&&a.output.push(b);},flush:function(a){a.output&&0<a.output.length&&(ka(E(a.output,0)),a.output=[]);}},vb={M:function(a,b){null===b||10===b?(y(E(a.output,0)),a.output=[]):0!=b&&a.output.push(b);},flush:function(a){a.output&&0<a.output.length&&(y(E(a.output,0)),a.output=[]);}},U={o:null,u:function(){return U.createNode(null,
"/",16895,0)},createNode:function(a,b,c,d){if(24576===(c&61440)||4096===(c&61440))throw new T(63);U.o||(U.o={dir:{node:{v:U.h.v,s:U.h.s,lookup:U.h.lookup,G:U.h.G,rename:U.h.rename,unlink:U.h.unlink,rmdir:U.h.rmdir,readdir:U.h.readdir,symlink:U.h.symlink},stream:{D:U.l.D}},file:{node:{v:U.h.v,s:U.h.s},stream:{D:U.l.D,read:U.l.read,write:U.l.write,P:U.l.P,X:U.l.X,Z:U.l.Z}},link:{node:{v:U.h.v,s:U.h.s,readlink:U.h.readlink},stream:{}},R:{node:{v:U.h.v,s:U.h.s},stream:wb}});c=xb(a,b,c,d);16384===(c.mode&
61440)?(c.h=U.o.dir.node,c.l=U.o.dir.stream,c.g={}):32768===(c.mode&61440)?(c.h=U.o.file.node,c.l=U.o.file.stream,c.m=0,c.g=null):40960===(c.mode&61440)?(c.h=U.o.link.node,c.l=U.o.link.stream):8192===(c.mode&61440)&&(c.h=U.o.R.node,c.l=U.o.R.stream);c.timestamp=Date.now();a&&(a.g[b]=c,a.timestamp=c.timestamp);return c},la:function(a){return a.g?a.g.subarray?a.g.subarray(0,a.m):new Uint8Array(a.g):new Uint8Array(0)},S:function(a,b){var c=a.g?a.g.length:0;c>=b||(b=Math.max(b,c*(1048576>c?2:1.125)>>>
0),0!=c&&(b=Math.max(b,256)),c=a.g,a.g=new Uint8Array(b),0<a.m&&a.g.set(c.subarray(0,a.m),0));},ga:function(a,b){if(a.m!=b)if(0==b)a.g=null,a.m=0;else {var c=a.g;a.g=new Uint8Array(b);c&&a.g.set(c.subarray(0,Math.min(b,a.m)));a.m=b;}},h:{v:function(a){var b={};b.dev=8192===(a.mode&61440)?a.id:1;b.ino=a.id;b.mode=a.mode;b.nlink=1;b.uid=0;b.gid=0;b.rdev=a.rdev;16384===(a.mode&61440)?b.size=4096:32768===(a.mode&61440)?b.size=a.m:40960===(a.mode&61440)?b.size=a.link.length:b.size=0;b.atime=new Date(a.timestamp);
b.mtime=new Date(a.timestamp);b.ctime=new Date(a.timestamp);b.da=4096;b.blocks=Math.ceil(b.size/b.da);return b},s:function(a,b){void 0!==b.mode&&(a.mode=b.mode);void 0!==b.timestamp&&(a.timestamp=b.timestamp);void 0!==b.size&&U.ga(a,b.size);},lookup:function(){throw yb[44];},G:function(a,b,c,d){return U.createNode(a,b,c,d)},rename:function(a,b,c){if(16384===(a.mode&61440)){try{var d=zb(b,c);}catch(f){}if(d)for(var e in d.g)throw new T(55);}delete a.parent.g[a.name];a.parent.timestamp=Date.now();a.name=
c;b.g[c]=a;b.timestamp=a.parent.timestamp;a.parent=b;},unlink:function(a,b){delete a.g[b];a.timestamp=Date.now();},rmdir:function(a,b){var c=zb(a,b),d;for(d in c.g)throw new T(55);delete a.g[b];a.timestamp=Date.now();},readdir:function(a){var b=[".",".."],c;for(c in a.g)a.g.hasOwnProperty(c)&&b.push(c);return b},symlink:function(a,b,c){a=U.createNode(a,b,41471,0);a.link=c;return a},readlink:function(a){if(40960!==(a.mode&61440))throw new T(28);return a.link}},l:{read:function(a,b,c,d,e){var f=a.node.g;
if(e>=a.node.m)return 0;a=Math.min(a.node.m-e,d);if(8<a&&f.subarray)b.set(f.subarray(e,e+a),c);else for(d=0;d<a;d++)b[c+d]=f[e+d];return a},write:function(a,b,c,d,e,f){b.buffer===G.buffer&&(f=!1);if(!d)return 0;a=a.node;a.timestamp=Date.now();if(b.subarray&&(!a.g||a.g.subarray)){if(f)return a.g=b.subarray(c,c+d),a.m=d;if(0===a.m&&0===e)return a.g=b.slice(c,c+d),a.m=d;if(e+d<=a.m)return a.g.set(b.subarray(c,c+d),e),d}U.S(a,e+d);if(a.g.subarray&&b.subarray)a.g.set(b.subarray(c,c+d),e);else for(f=0;f<
d;f++)a.g[e+f]=b[c+f];a.m=Math.max(a.m,e+d);return d},D:function(a,b,c){1===c?b+=a.position:2===c&&32768===(a.node.mode&61440)&&(b+=a.node.m);if(0>b)throw new T(28);return b},P:function(a,b,c){U.S(a.node,b+c);a.node.m=Math.max(a.node.m,b+c);},X:function(a,b,c,d,e){if(32768!==(a.node.mode&61440))throw new T(43);a=a.node.g;if(e&2||a.buffer!==F){if(0<c||c+b<a.length)a.subarray?a=a.subarray(c,c+b):a=Array.prototype.slice.call(a,c,c+b);c=!0;B();b=void 0;if(!b)throw new T(48);G.set(a,b);}else c=!1,b=a.byteOffset;
return {na:b,ja:c}},Z:function(a,b,c,d,e){if(32768!==(a.node.mode&61440))throw new T(43);if(e&2)return 0;U.l.write(a,b,0,d,c,!1);return 0}}},Ab=null,Bb={},Cb=[],Db=1,V=null,Eb=!0,T=null,yb={},W=(a,b={})=>{a=pb("/",a);if(!a)return {path:"",node:null};b=Object.assign({U:!0,N:0},b);if(8<b.N)throw new T(32);a=kb(a.split("/").filter(h=>!!h),!1);for(var c=Ab,d="/",e=0;e<a.length;e++){var f=e===a.length-1;if(f&&b.parent)break;c=zb(c,a[e]);d=lb(d+"/"+a[e]);c.H&&(!f||f&&b.U)&&(c=c.H.root);if(!f||b.T)for(f=0;40960===
(c.mode&61440);)if(c=Fb(d),d=pb(mb(d),c),c=W(d,{N:b.N+1}).node,40<f++)throw new T(32);}return {path:d,node:c}},Gb=a=>{for(var b;;){if(a===a.parent)return a=a.u.Y,b?"/"!==a[a.length-1]?a+"/"+b:a+b:a;b=b?a.name+"/"+b:a.name;a=a.parent;}},Hb=(a,b)=>{for(var c=0,d=0;d<b.length;d++)c=(c<<5)-c+b.charCodeAt(d)|0;return (a+c>>>0)%V.length},zb=(a,b)=>{var c;if(c=(c=Ib(a,"x"))?c:a.h.lookup?0:2)throw new T(c,a);for(c=V[Hb(a.id,b)];c;c=c.fa){var d=c.name;if(c.parent.id===a.id&&d===b)return c}return a.h.lookup(a,
b)},xb=(a,b,c,d)=>{a=new Jb(a,b,c,d);b=Hb(a.parent.id,a.name);a.fa=V[b];return V[b]=a},Kb={r:0,"r+":2,w:577,"w+":578,a:1089,"a+":1090},Lb=a=>{var b=["r","w","rw"][a&3];a&512&&(b+="w");return b},Ib=(a,b)=>{if(Eb)return 0;if(!b.includes("r")||a.mode&292){if(b.includes("w")&&!(a.mode&146)||b.includes("x")&&!(a.mode&73))return 2}else return 2;return 0},Mb=(a,b)=>{try{return zb(a,b),20}catch(c){}return Ib(a,"wx")},Nb=()=>{for(var a=0;4096>=a;a++)if(!Cb[a])return a;throw new T(33);},Ob=a=>{X||(X=function(){this.F=
{};},X.prototype={},Object.defineProperties(X.prototype,{object:{get:function(){return this.node},set:function(c){this.node=c;}},flags:{get:function(){return this.F.flags},set:function(c){this.F.flags=c;}},position:{get:function(){return this.F.position},set:function(c){this.F.position=c;}}}));a=Object.assign(new X,a);var b=Nb();a.fd=b;return Cb[b]=a},wb={open:a=>{a.l=Bb[a.node.rdev].l;a.l.open&&a.l.open(a);},D:()=>{throw new T(70);}},sb=(a,b)=>{Bb[a]={l:b};},Pb=(a,b)=>{var c="/"===b,d=!b;if(c&&Ab)throw new T(10);
if(!c&&!d){var e=W(b,{U:!1});b=e.path;e=e.node;if(e.H)throw new T(10);if(16384!==(e.mode&61440))throw new T(54);}b={type:a,ma:{},Y:b,ea:[]};a=a.u(b);a.u=b;b.root=a;c?Ab=a:e&&(e.H=b,e.u&&e.u.ea.push(b));},Y=(a,b,c)=>{var d=W(a,{parent:!0}).node;a=nb(a);if(!a||"."===a||".."===a)throw new T(28);var e=Mb(d,a);if(e)throw new T(e);if(!d.h.G)throw new T(63);return d.h.G(d,a,b,c)},Qb=(a,b,c)=>{"undefined"==typeof c&&(c=b,b=438);Y(a,b|8192,c);},Rb=(a,b)=>{if(!pb(a))throw new T(44);var c=W(b,{parent:!0}).node;
if(!c)throw new T(44);b=nb(b);var d=Mb(c,b);if(d)throw new T(d);if(!c.h.symlink)throw new T(63);c.h.symlink(c,b,a);},Fb=a=>{a=W(a).node;if(!a)throw new T(44);if(!a.h.readlink)throw new T(28);return pb(Gb(a.parent),a.h.readlink(a))},Tb=(a,b)=>{if(""===a)throw new T(44);if("string"==typeof b){var c=Kb[b];if("undefined"==typeof c)throw Error("Unknown file open mode: "+b);b=c;}var d=b&64?("undefined"==typeof d?438:d)&4095|32768:0;if("object"==typeof a)var e=a;else {a=lb(a);try{e=W(a,{T:!(b&131072)}).node;}catch(f){}}c=
!1;if(b&64)if(e){if(b&128)throw new T(20);}else e=Y(a,d,0),c=!0;if(!e)throw new T(44);8192===(e.mode&61440)&&(b&=-513);if(b&65536&&16384!==(e.mode&61440))throw new T(54);if(!c&&(d=e?40960===(e.mode&61440)?32:16384===(e.mode&61440)&&("r"!==Lb(b)||b&512)?31:Ib(e,Lb(b)):44))throw new T(d);if(b&512&&!c){d=e;d="string"==typeof d?W(d,{T:!0}).node:d;if(!d.h.s)throw new T(63);if(16384===(d.mode&61440))throw new T(31);if(32768!==(d.mode&61440))throw new T(28);if(c=Ib(d,"w"))throw new T(c);d.h.s(d,{size:0,
timestamp:Date.now()});}b&=-131713;e=Ob({node:e,path:Gb(e),flags:b,seekable:!0,position:0,l:e.l,pa:[],error:!1});e.l.open&&e.l.open(e);!g.logReadFiles||b&1||(Sb||(Sb={}),a in Sb||(Sb[a]=1));},Ub=()=>{T||(T=function(a,b){this.node=b;this.message="FS error";},T.prototype=Error(),T.prototype.constructor=T,[44].forEach(a=>{yb[a]=new T(a);yb[a].stack="<generic error, no stack>";}));},Vb,Wb=(a,b)=>{var c=0;a&&(c|=365);b&&(c|=146);return c},Z=(a,b,c)=>{a=lb("/dev/"+a);var d=Wb(!!b,!!c);Xb||(Xb=64);var e=Xb++<<
8|0;sb(e,{open:f=>{f.seekable=!1;},close:()=>{c&&c.buffer&&c.buffer.length&&c(10);},read:(f,h,m,p)=>{for(var q=0,n=0;n<p;n++){try{var r=b();}catch(C){throw new T(29);}if(void 0===r&&0===q)throw new T(6);if(null===r||void 0===r)break;q++;h[m+n]=r;}q&&(f.node.timestamp=Date.now());return q},write:(f,h,m,p)=>{for(var q=0;q<p;q++)try{c(h[m+q]);}catch(n){throw new T(29);}p&&(f.node.timestamp=Date.now());return q}});Qb(a,d,e);},Xb,X,Sb;
function Yb(a){if(!noExitRuntime){if(g.onExit)g.onExit(a);la=!0;}k(a,new ja(a));}function Jb(a,b,c,d){a||(a=this);this.parent=a;this.u=a.u;this.H=null;this.id=Db++;this.name=b;this.mode=c;this.h={};this.l={};this.rdev=d;}Object.defineProperties(Jb.prototype,{read:{get:function(){return 365===(this.mode&365)},set:function(a){a?this.mode|=365:this.mode&=-366;}},write:{get:function(){return 146===(this.mode&146)},set:function(a){a?this.mode|=146:this.mode&=-147;}}});Ub();V=Array(4096);Pb(U,"/");
Y("/tmp",16895,0);Y("/home",16895,0);Y("/home/web_user",16895,0);(()=>{Y("/dev",16895,0);sb(259,{read:()=>0,write:(b,c,d,e)=>e});Qb("/dev/null",259);rb(1280,ub);rb(1536,vb);Qb("/dev/tty",1280);Qb("/dev/tty1",1536);var a=ob();Z("random",a);Z("urandom",a);Y("/dev/shm",16895,0);Y("/dev/shm/tmp",16895,0);})();
(()=>{Y("/proc",16895,0);var a=Y("/proc/self",16895,0);Y("/proc/self/fd",16895,0);Pb({u:()=>{var b=xb(a,"fd",16895,73);b.h={lookup:(c,d)=>{var e=Cb[+d];if(!e)throw new T(8);c={parent:null,u:{Y:"fake"},h:{readlink:()=>e.path}};return c.parent=c}};return b}},"/proc/self/fd");})();var Q={__heap_base:Sa,__indirect_function_table:I,__memory_base:eb,__stack_pointer:fb,__table_base:gb,emscripten_asm_const_int:ib,emscripten_resize_heap:jb,memory:D};
(function(){function a(e,f){e=e.exports;e=Ya(e,1024);g.asm=e;f=Ja(f);f.B&&(z=f.B.concat(z));La(e);ua.unshift(g.asm.__wasm_call_ctors);ya.push(g.asm.__wasm_apply_data_relocs);Ca();}function b(e){a(e.instance,e.module);}function c(e){return Ga().then(function(f){return WebAssembly.instantiate(f,d)}).then(function(f){return f}).then(e,function(f){y("failed to asynchronously prepare wasm: "+f);B(f);})}var d={env:Q,wasi_snapshot_preview1:Q,"GOT.mem":new Proxy(Q,O),"GOT.func":new Proxy(Q,O)};Ba();if(g.instantiateWasm)try{return g.instantiateWasm(d,
a)}catch(e){return y("Module.instantiateWasm callback failed with error: "+e),!1}(function(){return A||"function"!=typeof WebAssembly.instantiateStreaming||Da()||M.startsWith("file://")||t||"function"!=typeof fetch?c(b):fetch(M,{credentials:"same-origin"}).then(function(e){return WebAssembly.instantiateStreaming(e,d).then(b,function(f){y("wasm streaming compile failed: "+f);y("falling back to ArrayBuffer instantiation");return c(b)})})})().catch(ba);return {}})();
g.___wasm_call_ctors=function(){return (g.___wasm_call_ctors=g.asm.__wasm_call_ctors).apply(null,arguments)};g.___wasm_apply_data_relocs=function(){return (g.___wasm_apply_data_relocs=g.asm.__wasm_apply_data_relocs).apply(null,arguments)};g._split_secret=function(){return (g._split_secret=g.asm.split_secret).apply(null,arguments)};var Ua=g._malloc=function(){return (Ua=g._malloc=g.asm.malloc).apply(null,arguments)};
g._restore_secret=function(){return (g._restore_secret=g.asm.restore_secret).apply(null,arguments)};var Ra=g._setThrew=function(){return (Ra=g._setThrew=g.asm.setThrew).apply(null,arguments)},Pa=g.stackSave=function(){return (Pa=g.stackSave=g.asm.stackSave).apply(null,arguments)},Qa=g.stackRestore=function(){return (Qa=g.stackRestore=g.asm.stackRestore).apply(null,arguments)},Zb=g.stackAlloc=function(){return (Zb=g.stackAlloc=g.asm.stackAlloc).apply(null,arguments)},$b;
L=function ac(){$b||bc();$b||(L=ac);};function cc(a){var b=g._main;if(b){a=a||[];a.unshift(ea);var c=a.length,d=Zb(4*(c+1)),e=d>>2;a.forEach(h=>{var m=H,p=e++,q=oa(h)+1,n=Zb(q);na(h,G,n,q);m[p]=n;});H[e]=0;try{var f=b(c,d);Yb(f);}catch(h){h instanceof ja||"unwind"==h||k(1,h);}}}var dc=!1;
function bc(){function a(){if(!$b&&($b=!0,g.calledRun=!0,!la)){J=!0;P(ya);g.noFSInit||Vb||(Vb=!0,Ub(),g.stdin=g.stdin,g.stdout=g.stdout,g.stderr=g.stderr,g.stdin?Z("stdin",g.stdin):Rb("/dev/tty","/dev/stdin"),g.stdout?Z("stdout",null,g.stdout):Rb("/dev/tty","/dev/stdout"),g.stderr?Z("stderr",null,g.stderr):Rb("/dev/tty1","/dev/stderr"),Tb("/dev/stdin",0),Tb("/dev/stdout",1),Tb("/dev/stderr",1));Eb=!1;P(ua);P(va);aa(g);if(g.onRuntimeInitialized)g.onRuntimeInitialized();ec&&cc(b);if(g.postRun)for("function"==
typeof g.postRun&&(g.postRun=[g.postRun]);g.postRun.length;){var c=g.postRun.shift();xa.unshift(c);}P(xa);}}var b=b||da;if(!(0<K)){if(!dc&&(db(),dc=!0,0<K))return;if(g.preRun)for("function"==typeof g.preRun&&(g.preRun=[g.preRun]);g.preRun.length;)za();P(ta);0<K||(g.setStatus?(g.setStatus("Running..."),setTimeout(function(){setTimeout(function(){g.setStatus("");},1);a();},1)):a());}}if(g.preInit)for("function"==typeof g.preInit&&(g.preInit=[g.preInit]);0<g.preInit.length;)g.preInit.pop()();var ec=!0;
g.noInitialRun&&(ec=!1);bc();


  return shamirMethodsModule.ready
}
);
})();

// Copyright (C) 2022 Deliberative Technologies P.C.
const splitSecret = async (secret, sharesLen, threshold, module) => {
    const secretLen = secret.length;
    if (secretLen < 2)
        throw new Error("Need more data.");
    const wasmMemory = module
        ? module.wasmMemory
        : memory.splitSecretMemory(secretLen, sharesLen, threshold);
    let offset = 0;
    const secretArray = new Uint8Array(wasmMemory.buffer, offset, secretLen);
    secretArray.set([...secret]);
    offset += secretLen;
    const sharesArray = new Uint8Array(wasmMemory.buffer, offset, sharesLen * (secretLen + 1));
    const shamirModule = module || (await shamirMethodsModule({ wasmMemory }));
    const result = shamirModule._split_secret(sharesLen, threshold, secretLen, secretArray.byteOffset, sharesArray.byteOffset);
    const values = [];
    switch (result) {
        case 0: {
            for (let i = 0; i < sharesLen; i++) {
                values.push(sharesArray.slice(i * (secretLen + 1), (i + 1) * (secretLen + 1)));
            }
            return values;
        }
        case -1: {
            throw new Error("Threshold is less than 2");
        }
        case -2: {
            throw new Error("Shares are less than threshold");
        }
        case -3: {
            throw new Error("Shares exceed 255");
        }
        default: {
            throw new Error("Unexpected error occured");
        }
    }
};

// Copyright (C) 2022 Deliberative Technologies P.C.
const restoreSecret = async (shares, module) => {
    const sharesLen = shares.length;
    const shareItemLen = shares[0].length;
    const lengthVerification = shares.every((v) => v.length === shareItemLen);
    if (!lengthVerification)
        throw new Error("Shares length varies.");
    const secretLen = shareItemLen - 1;
    const wasmMemory = module
        ? module.wasmMemory
        : memory.restoreSecretMemory(secretLen, sharesLen);
    let offset = 0;
    const sharesArray = new Uint8Array(wasmMemory.buffer, offset, sharesLen * (secretLen + 1));
    for (let i = 0; i < sharesLen; i++) {
        sharesArray.set(shares[i], i * (secretLen + 1));
    }
    offset += sharesLen * (secretLen + 1);
    const secretArray = new Uint8Array(wasmMemory.buffer, offset, secretLen);
    const shamirModule = await shamirMethodsModule({ wasmMemory });
    const result = shamirModule._restore_secret(sharesLen, secretLen, sharesArray.byteOffset, secretArray.byteOffset);
    switch (result) {
        case 0: {
            return new Uint8Array([...secretArray]);
        }
        case -1: {
            throw new Error("Need at most 255 shares.");
        }
        case -2: {
            throw new Error("Not enough shares provided.");
        }
        default: {
            throw new Error("An unexpected error occured.");
        }
    }
};

// Copyright (C) 2022 Deliberative Technologies P.C.
var shamir = {
    splitSecret,
    restoreSecret,
    memory,
};

var utilsMethodsModule = (() => {
  var _scriptDir = typeof document !== 'undefined' && document.currentScript ? document.currentScript.src : undefined;
  if (typeof __filename !== 'undefined') _scriptDir = _scriptDir || __filename;
  return (
function(utilsMethodsModule) {
  utilsMethodsModule = utilsMethodsModule || {};
var g;g||(g=typeof utilsMethodsModule !== 'undefined' ? utilsMethodsModule : {});var aa,ba;g.ready=new Promise(function(a,b){aa=a;ba=b;});var ca=Object.assign({},g),da=[],ea="./this.program",k=(a,b)=>{throw b;},fa="object"==typeof window,l="function"==typeof importScripts,t="object"==typeof process&&"object"==typeof process.versions&&"string"==typeof process.versions.node,u="",ha,v,w,fs,x,ia;
if(t)u=l?require("path").dirname(u)+"/":__dirname+"/",ia=()=>{x||(fs=require("fs"),x=require("path"));},ha=function(a,b){ia();a=x.normalize(a);return fs.readFileSync(a,b?void 0:"utf8")},w=a=>{a=ha(a,!0);a.buffer||(a=new Uint8Array(a));return a},v=(a,b,c)=>{ia();a=x.normalize(a);fs.readFile(a,function(d,e){d?c(d):b(e.buffer);});},1<process.argv.length&&(ea=process.argv[1].replace(/\\/g,"/")),da=process.argv.slice(2),k=(a,b)=>{if(noExitRuntime)throw process.exitCode=a,b;b instanceof ja||y("exiting due to exception: "+
b);process.exit(a);},g.inspect=function(){return "[Emscripten Module object]"};else if(fa||l)l?u=self.location.href:"undefined"!=typeof document&&document.currentScript&&(u=document.currentScript.src),_scriptDir&&(u=_scriptDir),0!==u.indexOf("blob:")?u=u.substr(0,u.replace(/[?#].*/,"").lastIndexOf("/")+1):u="",ha=a=>{var b=new XMLHttpRequest;b.open("GET",a,!1);b.send(null);return b.responseText},l&&(w=a=>{var b=new XMLHttpRequest;b.open("GET",a,!1);b.responseType="arraybuffer";b.send(null);return new Uint8Array(b.response)}),
v=(a,b,c)=>{var d=new XMLHttpRequest;d.open("GET",a,!0);d.responseType="arraybuffer";d.onload=()=>{200==d.status||0==d.status&&d.response?b(d.response):c();};d.onerror=c;d.send(null);};var ka=g.print||console.log.bind(console),y=g.printErr||console.warn.bind(console);Object.assign(g,ca);ca=null;g.arguments&&(da=g.arguments);g.thisProgram&&(ea=g.thisProgram);g.quit&&(k=g.quit);var z=g.dynamicLibraries||[],A;g.wasmBinary&&(A=g.wasmBinary);var noExitRuntime=g.noExitRuntime||!0;
"object"!=typeof WebAssembly&&B("no native wasm support detected");var D,la=!1,ma="undefined"!=typeof TextDecoder?new TextDecoder("utf8"):void 0;
function E(a,b,c){var d=b+c;for(c=b;a[c]&&!(c>=d);)++c;if(16<c-b&&a.buffer&&ma)return ma.decode(a.subarray(b,c));for(d="";b<c;){var e=a[b++];if(e&128){var f=a[b++]&63;if(192==(e&224))d+=String.fromCharCode((e&31)<<6|f);else {var h=a[b++]&63;e=224==(e&240)?(e&15)<<12|f<<6|h:(e&7)<<18|f<<12|h<<6|a[b++]&63;65536>e?d+=String.fromCharCode(e):(e-=65536,d+=String.fromCharCode(55296|e>>10,56320|e&1023));}}else d+=String.fromCharCode(e);}return d}
function na(a,b,c,d){if(!(0<d))return 0;var e=c;d=c+d-1;for(var f=0;f<a.length;++f){var h=a.charCodeAt(f);if(55296<=h&&57343>=h){var m=a.charCodeAt(++f);h=65536+((h&1023)<<10)|m&1023;}if(127>=h){if(c>=d)break;b[c++]=h;}else {if(2047>=h){if(c+1>=d)break;b[c++]=192|h>>6;}else {if(65535>=h){if(c+2>=d)break;b[c++]=224|h>>12;}else {if(c+3>=d)break;b[c++]=240|h>>18;b[c++]=128|h>>12&63;}b[c++]=128|h>>6&63;}b[c++]=128|h&63;}}b[c]=0;return c-e}
function oa(a){for(var b=0,c=0;c<a.length;++c){var d=a.charCodeAt(c);127>=d?b++:2047>=d?b+=2:55296<=d&&57343>=d?(b+=4,++c):b+=3;}return b}var F,G,pa,H,qa;function ra(a){F=a;g.HEAP8=G=new Int8Array(a);g.HEAP16=new Int16Array(a);g.HEAP32=H=new Int32Array(a);g.HEAPU8=pa=new Uint8Array(a);g.HEAPU16=new Uint16Array(a);g.HEAPU32=new Uint32Array(a);g.HEAPF32=new Float32Array(a);g.HEAPF64=qa=new Float64Array(a);}var sa=g.INITIAL_MEMORY||2097152;
g.wasmMemory?D=g.wasmMemory:D=new WebAssembly.Memory({initial:sa/65536,maximum:1600});D&&(F=D.buffer);sa=F.byteLength;ra(F);var I=new WebAssembly.Table({initial:5,element:"anyfunc"}),ta=[],ua=[],va=[],xa=[],ya=[],J=!1;function za(){var a=g.preRun.shift();ta.unshift(a);}var K=0,L=null;function Ba(){K++;g.monitorRunDependencies&&g.monitorRunDependencies(K);}
function Ca(){K--;g.monitorRunDependencies&&g.monitorRunDependencies(K);if(0==K&&(L)){var a=L;L=null;a();}}function B(a){if(g.onAbort)g.onAbort(a);a="Aborted("+a+")";y(a);la=!0;a=new WebAssembly.RuntimeError(a+". Build with -sASSERTIONS for more info.");ba(a);throw a;}function Da(){return M.startsWith("data:application/octet-stream;base64,")}var M;M="utilsMethodsModule.wasm";if(!Da()){var Ea=M;M=g.locateFile?g.locateFile(Ea,u):u+Ea;}
function Fa(){var a=M;try{if(a==M&&A)return new Uint8Array(A);if(w)return w(a);throw "both async and sync fetching of the wasm failed";}catch(b){B(b);}}
function Ga(){if(!A&&(fa||l)){if("function"==typeof fetch&&!M.startsWith("file://"))return fetch(M,{credentials:"same-origin"}).then(function(a){if(!a.ok)throw "failed to load wasm binary file at '"+M+"'";return a.arrayBuffer()}).catch(function(){return Fa()});if(v)return new Promise(function(a,b){v(M,function(c){a(new Uint8Array(c));},b);})}return Promise.resolve().then(function(){return Fa()})}
var Ha={4364:()=>g.J(),4400:()=>{if(void 0===g.J)try{var a="object"===typeof window?window:self,b="undefined"!==typeof a.crypto?a.crypto:a.msCrypto;a=function(){var d=new Uint32Array(1);b.getRandomValues(d);return d[0]>>>0};a();g.J=a;}catch(d){try{var c=require("crypto");a=function(){var e=c.randomBytes(4);return (e[0]<<24|e[1]<<16|e[2]<<8|e[3])>>>0};a();g.J=a;}catch(e){throw "No secure random number generator found";}}}};
function ja(a){this.name="ExitStatus";this.message="Program terminated with exit("+a+")";this.status=a;}var N={},Ia=new Set([]),O={get:function(a,b){(a=N[b])||(a=N[b]=new WebAssembly.Global({value:"i32",mutable:!0}));Ia.has(b)||(a.required=!0);return a}};function P(a){for(;0<a.length;)a.shift()(g);}
function Ja(a){function b(){for(var n=0,r=1;;){var C=a[e++];n+=(C&127)*r;r*=128;if(!(C&128))break}return n}function c(){var n=b();e+=n;return E(a,e-n,n)}function d(n,r){if(n)throw Error(r);}var e=0,f=0,h="dylink.0";a instanceof WebAssembly.Module?(f=WebAssembly.Module.customSections(a,h),0===f.length&&(h="dylink",f=WebAssembly.Module.customSections(a,h)),d(0===f.length,"need dylink section"),a=new Uint8Array(f[0]),f=a.length):(f=1836278016==(new Uint32Array((new Uint8Array(a.subarray(0,24))).buffer))[0],
d(!f,"need to see wasm magic number"),d(0!==a[8],"need the dylink section to be first"),e=9,f=b(),f=e+f,h=c());var m={B:[],ia:new Set,aa:new Set};if("dylink"==h){m.K=b();m.W=b();m.I=b();m.ha=b();h=b();for(var p=0;p<h;++p){var q=c();m.B.push(q);}}else for(d("dylink.0"!==h);e<f;)if(h=a[e++],p=b(),1===h)m.K=b(),m.W=b(),m.I=b(),m.ha=b();else if(2===h)for(h=b(),p=0;p<h;++p)q=c(),m.B.push(q);else if(3===h)for(h=b();h--;)p=c(),q=b(),q&256&&m.ia.add(p);else if(4===h)for(h=b();h--;)c(),p=c(),q=b(),1==(q&3)&&
m.aa.add(p);else e+=p;return m}function Ka(a){var b=["stackAlloc","stackSave","stackRestore"];return 0==a.indexOf("dynCall_")||b.includes(a)?a:"_"+a}function La(a){for(var b in a)if(a.hasOwnProperty(b)){Q.hasOwnProperty(b)||(Q[b]=a[b]);var c=Ka(b);g.hasOwnProperty(c)||(g[c]=a[b]);"__main_argc_argv"==b&&(g._main=a[b]);}}var Ma={},R=[];function Na(a){var b=R[a];b||(a>=R.length&&(R.length=a+1),R[a]=b=I.get(a));return b}
function Oa(a){return function(){var b=Pa();try{var c=arguments[0],d=Array.prototype.slice.call(arguments,1);if(a.includes("j")){var e=g["dynCall_"+a];var f=d&&d.length?e.apply(null,[c].concat(d)):e.call(null,c);}else f=Na(c).apply(null,d);return f}catch(h){Qa(b);if(h!==h+0)throw h;Ra(1,0);}}}var Sa=1055264;function Ta(a){if(J)return Ua(a);var b=Sa;Sa=a=b+a+15&-16;N.__heap_base.value=a;return b}function Va(a,b){if(S)for(var c=a;c<a+b;c++){var d=Na(c);d&&S.set(d,c);}}var S=void 0,Wa=[];
function Xa(a,b){S||(S=new WeakMap,Va(0,I.length));if(S.has(a))return S.get(a);if(Wa.length)var c=Wa.pop();else {try{I.grow(1);}catch(m){if(!(m instanceof RangeError))throw m;throw "Unable to grow wasm table. Set ALLOW_TABLE_GROWTH.";}c=I.length-1;}try{var d=c;I.set(d,a);R[d]=I.get(d);}catch(m){if(!(m instanceof TypeError))throw m;if("function"==typeof WebAssembly.Function){d=WebAssembly.Function;for(var e={i:"i32",j:"i64",f:"f32",d:"f64",p:"i32"},f={parameters:[],results:"v"==b[0]?[]:[e[b[0]]]},h=1;h<
b.length;++h)f.parameters.push(e[b[h]]);d=new d(f,a);}else {d=[1,96];e=b.slice(0,1);b=b.slice(1);f={i:127,p:127,j:126,f:125,d:124};h=b.length;128>h?d.push(h):d.push(h%128|128,h>>7);for(h=0;h<b.length;++h)d.push(f[b[h]]);"v"==e?d.push(0):d.push(1,f[e]);b=[0,97,115,109,1,0,0,0,1];e=d.length;128>e?b.push(e):b.push(e%128|128,e>>7);b.push.apply(b,d);b.push(2,7,1,1,101,1,102,0,0,7,5,1,1,102,0,0);d=new WebAssembly.Module(new Uint8Array(b));d=(new WebAssembly.Instance(d,{e:{f:a}})).exports.f;}b=c;I.set(b,d);
R[b]=I.get(b);}S.set(a,c);return c}
function Ya(a,b){var c={},d;for(d in a){var e=a[d];"object"==typeof e&&(e=e.value);"number"==typeof e&&(e+=b);c[d]=e;}a=void 0;for(var f in c)!"__cpp_exception __c_longjmp __wasm_apply_data_relocs __dso_handle __tls_size __tls_align __set_stack_limits _emscripten_tls_init __wasm_init_tls __wasm_call_ctors".split(" ").includes(f)&&(b=c[f],f.startsWith("orig$")&&(f=f.split("$")[1],a=!0),N[f]||(N[f]=new WebAssembly.Global({value:"i32",mutable:!0})),a||0==N[f].value)&&("function"==typeof b?N[f].value=
Xa(b):"number"==typeof b?N[f].value=b:"bigint"==typeof b?N[f].value=Number(b):y("unhandled export type for `"+f+"`: "+typeof b));return c}function Za(a,b){var c;b&&(c=Q["orig$"+a]);c||(c=Q[a])&&c.oa&&(c=void 0);c||(c=g[Ka(a)]);!c&&a.startsWith("invoke_")&&(c=Oa(a.split("_")[1]));return c}function $a(a,b){return Math.ceil(a/b)*b}
function ab(a,b){function c(){function e(n){Va(m,d.I);p=Ya(n.exports,h);b.ba||bb();(n=p.__wasm_call_ctors)&&(J?n():ua.push(n));(n=p.__wasm_apply_data_relocs)&&(J?n():ya.push(n));return p}var f=Math.pow(2,d.W);f=Math.max(f,16);var h=d.K?$a(Ta(d.K+f),f):0,m=d.I?I.length:0;f=m+d.I-I.length;0<f&&I.grow(f);var p;f=new Proxy({},{get:function(n,r){switch(r){case "__memory_base":return h;case "__table_base":return m}if(r in Q)return Q[r];if(!(r in n)){var C;n[r]=function(){if(!C){var wa=Za(r,!1);wa||(wa=
p[r]);C=wa;}return C.apply(null,arguments)};}return n[r]}});f={"GOT.mem":new Proxy({},O),"GOT.func":new Proxy({},O),env:f,qa:f};if(b.A)return a instanceof WebAssembly.Module?(f=new WebAssembly.Instance(a,f),Promise.resolve(e(f))):WebAssembly.instantiate(a,f).then(function(n){return e(n.instance)});var q=a instanceof WebAssembly.Module?a:new WebAssembly.Module(a);f=new WebAssembly.Instance(q,f);return e(f)}var d=Ja(a);Ia=d.aa;if(b.A)return d.B.reduce(function(e,f){return e.then(function(){return cb(f,
b)})},Promise.resolve()).then(function(){return c()});d.B.forEach(function(e){cb(e,b);});return c()}
function cb(a,b){function c(h){if(b.fs&&b.fs.ka(h)){var m=b.fs.readFile(h,{encoding:"binary"});m instanceof Uint8Array||(m=new Uint8Array(m));return b.A?Promise.resolve(m):m}if(b.A)return new Promise(function(p,q){v(h,n=>p(new Uint8Array(n)),q);});if(!w)throw Error(h+": file not found, and synchronous loading of external files is not available");return w(h)}function d(){if("undefined"!=typeof preloadedWasm&&preloadedWasm[a]){var h=preloadedWasm[a];return b.A?Promise.resolve(h):h}return b.A?c(a).then(function(m){return ab(m,
b)}):ab(c(a),b)}function e(h){f.global&&La(h);f.module=h;}b=b||{global:!0,L:!0};var f=Ma[a];if(f)return b.global&&!f.global&&(f.global=!0,"loading"!==f.module&&La(f.module)),b.L&&Infinity!==f.O&&(f.O=Infinity),f.O++,b.A?Promise.resolve(!0):!0;f={O:b.L?Infinity:1,name:a,module:"loading",global:b.global};Ma[a]=f;if(b.A)return d().then(function(h){e(h);return !0});e(d());return !0}
function bb(){for(var a in N)if(0==N[a].value){var b=Za(a,!0);if(b||N[a].required)if("function"==typeof b)N[a].value=Xa(b,b.$);else if("number"==typeof b)N[a].value=b;else throw Error("bad export type for `"+a+"`: "+typeof b);}}function db(){z.length?(Ba(),z.reduce(function(a,b){return a.then(function(){return cb(b,{A:!0,global:!0,L:!0,ba:!0})})},Promise.resolve()).then(function(){bb();Ca();})):bb();}
var eb=new WebAssembly.Global({value:"i32",mutable:!1},1024),fb=new WebAssembly.Global({value:"i32",mutable:!0},1055264),gb=new WebAssembly.Global({value:"i32",mutable:!1},1),hb=[];function ib(a,b,c){a-=1024;hb.length=0;var d;for(c>>=2;d=pa[b++];)c+=105!=d&c,hb.push(105==d?H[c]:qa[c++>>1]),++c;return Ha[a].apply(null,hb)}ib.$="ippp";
function jb(a){var b=pa.length;a>>>=0;if(104857600<a)return !1;for(var c=1;4>=c;c*=2){var d=b*(1+.2/c);d=Math.min(d,a+100663296);var e=Math;d=Math.max(a,d);e=e.min.call(e,104857600,d+(65536-d%65536)%65536);a:{try{D.grow(e-F.byteLength+65535>>>16);ra(D.buffer);var f=1;break a}catch(h){}f=void 0;}if(f)return !0}return !1}jb.$="ip";
var kb=(a,b)=>{for(var c=0,d=a.length-1;0<=d;d--){var e=a[d];"."===e?a.splice(d,1):".."===e?(a.splice(d,1),c++):c&&(a.splice(d,1),c--);}if(b)for(;c;c--)a.unshift("..");return a},lb=a=>{var b="/"===a.charAt(0),c="/"===a.substr(-1);(a=kb(a.split("/").filter(d=>!!d),!b).join("/"))||b||(a=".");a&&c&&(a+="/");return (b?"/":"")+a},mb=a=>{var b=/^(\/?|)([\s\S]*?)((?:\.{1,2}|[^\/]+?|)(\.[^.\/]*|))(?:[\/]*)$/.exec(a).slice(1);a=b[0];b=b[1];if(!a&&!b)return ".";b&&(b=b.substr(0,b.length-1));return a+b},nb=a=>
{if("/"===a)return "/";a=lb(a);a=a.replace(/\/$/,"");var b=a.lastIndexOf("/");return -1===b?a:a.substr(b+1)};function ob(){if("object"==typeof crypto&&"function"==typeof crypto.getRandomValues){var a=new Uint8Array(1);return ()=>{crypto.getRandomValues(a);return a[0]}}if(t)try{var b=require("crypto");return ()=>b.randomBytes(1)[0]}catch(c){}return ()=>B("randomDevice")}
function pb(){for(var a="",b=!1,c=arguments.length-1;-1<=c&&!b;c--){b=0<=c?arguments[c]:"/";if("string"!=typeof b)throw new TypeError("Arguments to path.resolve must be strings");if(!b)return "";a=b+"/"+a;b="/"===b.charAt(0);}a=kb(a.split("/").filter(d=>!!d),!b).join("/");return (b?"/":"")+a||"."}var qb=[];function rb(a,b){qb[a]={input:[],output:[],C:b};sb(a,tb);}
var tb={open:function(a){var b=qb[a.node.rdev];if(!b)throw new T(43);a.tty=b;a.seekable=!1;},close:function(a){a.tty.C.flush(a.tty);},flush:function(a){a.tty.C.flush(a.tty);},read:function(a,b,c,d){if(!a.tty||!a.tty.C.V)throw new T(60);for(var e=0,f=0;f<d;f++){try{var h=a.tty.C.V(a.tty);}catch(m){throw new T(29);}if(void 0===h&&0===e)throw new T(6);if(null===h||void 0===h)break;e++;b[c+f]=h;}e&&(a.node.timestamp=Date.now());return e},write:function(a,b,c,d){if(!a.tty||!a.tty.C.M)throw new T(60);try{for(var e=
0;e<d;e++)a.tty.C.M(a.tty,b[c+e]);}catch(f){throw new T(29);}d&&(a.node.timestamp=Date.now());return e}},ub={V:function(a){if(!a.input.length){var b=null;if(t){var c=Buffer.alloc(256),d=0;try{d=fs.readSync(process.stdin.fd,c,0,256,-1);}catch(e){if(e.toString().includes("EOF"))d=0;else throw e;}0<d?b=c.slice(0,d).toString("utf-8"):b=null;}else "undefined"!=typeof window&&"function"==typeof window.prompt?(b=window.prompt("Input: "),null!==b&&(b+="\n")):"function"==typeof readline&&(b=readline(),null!==
b&&(b+="\n"));if(!b)return null;c=Array(oa(b)+1);b=na(b,c,0,c.length);c.length=b;a.input=c;}return a.input.shift()},M:function(a,b){null===b||10===b?(ka(E(a.output,0)),a.output=[]):0!=b&&a.output.push(b);},flush:function(a){a.output&&0<a.output.length&&(ka(E(a.output,0)),a.output=[]);}},vb={M:function(a,b){null===b||10===b?(y(E(a.output,0)),a.output=[]):0!=b&&a.output.push(b);},flush:function(a){a.output&&0<a.output.length&&(y(E(a.output,0)),a.output=[]);}},U={o:null,u:function(){return U.createNode(null,
"/",16895,0)},createNode:function(a,b,c,d){if(24576===(c&61440)||4096===(c&61440))throw new T(63);U.o||(U.o={dir:{node:{v:U.h.v,s:U.h.s,lookup:U.h.lookup,G:U.h.G,rename:U.h.rename,unlink:U.h.unlink,rmdir:U.h.rmdir,readdir:U.h.readdir,symlink:U.h.symlink},stream:{D:U.l.D}},file:{node:{v:U.h.v,s:U.h.s},stream:{D:U.l.D,read:U.l.read,write:U.l.write,P:U.l.P,X:U.l.X,Z:U.l.Z}},link:{node:{v:U.h.v,s:U.h.s,readlink:U.h.readlink},stream:{}},R:{node:{v:U.h.v,s:U.h.s},stream:wb}});c=xb(a,b,c,d);16384===(c.mode&
61440)?(c.h=U.o.dir.node,c.l=U.o.dir.stream,c.g={}):32768===(c.mode&61440)?(c.h=U.o.file.node,c.l=U.o.file.stream,c.m=0,c.g=null):40960===(c.mode&61440)?(c.h=U.o.link.node,c.l=U.o.link.stream):8192===(c.mode&61440)&&(c.h=U.o.R.node,c.l=U.o.R.stream);c.timestamp=Date.now();a&&(a.g[b]=c,a.timestamp=c.timestamp);return c},la:function(a){return a.g?a.g.subarray?a.g.subarray(0,a.m):new Uint8Array(a.g):new Uint8Array(0)},S:function(a,b){var c=a.g?a.g.length:0;c>=b||(b=Math.max(b,c*(1048576>c?2:1.125)>>>
0),0!=c&&(b=Math.max(b,256)),c=a.g,a.g=new Uint8Array(b),0<a.m&&a.g.set(c.subarray(0,a.m),0));},ga:function(a,b){if(a.m!=b)if(0==b)a.g=null,a.m=0;else {var c=a.g;a.g=new Uint8Array(b);c&&a.g.set(c.subarray(0,Math.min(b,a.m)));a.m=b;}},h:{v:function(a){var b={};b.dev=8192===(a.mode&61440)?a.id:1;b.ino=a.id;b.mode=a.mode;b.nlink=1;b.uid=0;b.gid=0;b.rdev=a.rdev;16384===(a.mode&61440)?b.size=4096:32768===(a.mode&61440)?b.size=a.m:40960===(a.mode&61440)?b.size=a.link.length:b.size=0;b.atime=new Date(a.timestamp);
b.mtime=new Date(a.timestamp);b.ctime=new Date(a.timestamp);b.da=4096;b.blocks=Math.ceil(b.size/b.da);return b},s:function(a,b){void 0!==b.mode&&(a.mode=b.mode);void 0!==b.timestamp&&(a.timestamp=b.timestamp);void 0!==b.size&&U.ga(a,b.size);},lookup:function(){throw yb[44];},G:function(a,b,c,d){return U.createNode(a,b,c,d)},rename:function(a,b,c){if(16384===(a.mode&61440)){try{var d=zb(b,c);}catch(f){}if(d)for(var e in d.g)throw new T(55);}delete a.parent.g[a.name];a.parent.timestamp=Date.now();a.name=
c;b.g[c]=a;b.timestamp=a.parent.timestamp;a.parent=b;},unlink:function(a,b){delete a.g[b];a.timestamp=Date.now();},rmdir:function(a,b){var c=zb(a,b),d;for(d in c.g)throw new T(55);delete a.g[b];a.timestamp=Date.now();},readdir:function(a){var b=[".",".."],c;for(c in a.g)a.g.hasOwnProperty(c)&&b.push(c);return b},symlink:function(a,b,c){a=U.createNode(a,b,41471,0);a.link=c;return a},readlink:function(a){if(40960!==(a.mode&61440))throw new T(28);return a.link}},l:{read:function(a,b,c,d,e){var f=a.node.g;
if(e>=a.node.m)return 0;a=Math.min(a.node.m-e,d);if(8<a&&f.subarray)b.set(f.subarray(e,e+a),c);else for(d=0;d<a;d++)b[c+d]=f[e+d];return a},write:function(a,b,c,d,e,f){b.buffer===G.buffer&&(f=!1);if(!d)return 0;a=a.node;a.timestamp=Date.now();if(b.subarray&&(!a.g||a.g.subarray)){if(f)return a.g=b.subarray(c,c+d),a.m=d;if(0===a.m&&0===e)return a.g=b.slice(c,c+d),a.m=d;if(e+d<=a.m)return a.g.set(b.subarray(c,c+d),e),d}U.S(a,e+d);if(a.g.subarray&&b.subarray)a.g.set(b.subarray(c,c+d),e);else for(f=0;f<
d;f++)a.g[e+f]=b[c+f];a.m=Math.max(a.m,e+d);return d},D:function(a,b,c){1===c?b+=a.position:2===c&&32768===(a.node.mode&61440)&&(b+=a.node.m);if(0>b)throw new T(28);return b},P:function(a,b,c){U.S(a.node,b+c);a.node.m=Math.max(a.node.m,b+c);},X:function(a,b,c,d,e){if(32768!==(a.node.mode&61440))throw new T(43);a=a.node.g;if(e&2||a.buffer!==F){if(0<c||c+b<a.length)a.subarray?a=a.subarray(c,c+b):a=Array.prototype.slice.call(a,c,c+b);c=!0;B();b=void 0;if(!b)throw new T(48);G.set(a,b);}else c=!1,b=a.byteOffset;
return {na:b,ja:c}},Z:function(a,b,c,d,e){if(32768!==(a.node.mode&61440))throw new T(43);if(e&2)return 0;U.l.write(a,b,0,d,c,!1);return 0}}},Ab=null,Bb={},Cb=[],Db=1,V=null,Eb=!0,T=null,yb={},W=(a,b={})=>{a=pb("/",a);if(!a)return {path:"",node:null};b=Object.assign({U:!0,N:0},b);if(8<b.N)throw new T(32);a=kb(a.split("/").filter(h=>!!h),!1);for(var c=Ab,d="/",e=0;e<a.length;e++){var f=e===a.length-1;if(f&&b.parent)break;c=zb(c,a[e]);d=lb(d+"/"+a[e]);c.H&&(!f||f&&b.U)&&(c=c.H.root);if(!f||b.T)for(f=0;40960===
(c.mode&61440);)if(c=Fb(d),d=pb(mb(d),c),c=W(d,{N:b.N+1}).node,40<f++)throw new T(32);}return {path:d,node:c}},Gb=a=>{for(var b;;){if(a===a.parent)return a=a.u.Y,b?"/"!==a[a.length-1]?a+"/"+b:a+b:a;b=b?a.name+"/"+b:a.name;a=a.parent;}},Hb=(a,b)=>{for(var c=0,d=0;d<b.length;d++)c=(c<<5)-c+b.charCodeAt(d)|0;return (a+c>>>0)%V.length},zb=(a,b)=>{var c;if(c=(c=Ib(a,"x"))?c:a.h.lookup?0:2)throw new T(c,a);for(c=V[Hb(a.id,b)];c;c=c.fa){var d=c.name;if(c.parent.id===a.id&&d===b)return c}return a.h.lookup(a,
b)},xb=(a,b,c,d)=>{a=new Jb(a,b,c,d);b=Hb(a.parent.id,a.name);a.fa=V[b];return V[b]=a},Kb={r:0,"r+":2,w:577,"w+":578,a:1089,"a+":1090},Lb=a=>{var b=["r","w","rw"][a&3];a&512&&(b+="w");return b},Ib=(a,b)=>{if(Eb)return 0;if(!b.includes("r")||a.mode&292){if(b.includes("w")&&!(a.mode&146)||b.includes("x")&&!(a.mode&73))return 2}else return 2;return 0},Mb=(a,b)=>{try{return zb(a,b),20}catch(c){}return Ib(a,"wx")},Nb=()=>{for(var a=0;4096>=a;a++)if(!Cb[a])return a;throw new T(33);},Ob=a=>{X||(X=function(){this.F=
{};},X.prototype={},Object.defineProperties(X.prototype,{object:{get:function(){return this.node},set:function(c){this.node=c;}},flags:{get:function(){return this.F.flags},set:function(c){this.F.flags=c;}},position:{get:function(){return this.F.position},set:function(c){this.F.position=c;}}}));a=Object.assign(new X,a);var b=Nb();a.fd=b;return Cb[b]=a},wb={open:a=>{a.l=Bb[a.node.rdev].l;a.l.open&&a.l.open(a);},D:()=>{throw new T(70);}},sb=(a,b)=>{Bb[a]={l:b};},Pb=(a,b)=>{var c="/"===b,d=!b;if(c&&Ab)throw new T(10);
if(!c&&!d){var e=W(b,{U:!1});b=e.path;e=e.node;if(e.H)throw new T(10);if(16384!==(e.mode&61440))throw new T(54);}b={type:a,ma:{},Y:b,ea:[]};a=a.u(b);a.u=b;b.root=a;c?Ab=a:e&&(e.H=b,e.u&&e.u.ea.push(b));},Y=(a,b,c)=>{var d=W(a,{parent:!0}).node;a=nb(a);if(!a||"."===a||".."===a)throw new T(28);var e=Mb(d,a);if(e)throw new T(e);if(!d.h.G)throw new T(63);return d.h.G(d,a,b,c)},Qb=(a,b,c)=>{"undefined"==typeof c&&(c=b,b=438);Y(a,b|8192,c);},Rb=(a,b)=>{if(!pb(a))throw new T(44);var c=W(b,{parent:!0}).node;
if(!c)throw new T(44);b=nb(b);var d=Mb(c,b);if(d)throw new T(d);if(!c.h.symlink)throw new T(63);c.h.symlink(c,b,a);},Fb=a=>{a=W(a).node;if(!a)throw new T(44);if(!a.h.readlink)throw new T(28);return pb(Gb(a.parent),a.h.readlink(a))},Tb=(a,b)=>{if(""===a)throw new T(44);if("string"==typeof b){var c=Kb[b];if("undefined"==typeof c)throw Error("Unknown file open mode: "+b);b=c;}var d=b&64?("undefined"==typeof d?438:d)&4095|32768:0;if("object"==typeof a)var e=a;else {a=lb(a);try{e=W(a,{T:!(b&131072)}).node;}catch(f){}}c=
!1;if(b&64)if(e){if(b&128)throw new T(20);}else e=Y(a,d,0),c=!0;if(!e)throw new T(44);8192===(e.mode&61440)&&(b&=-513);if(b&65536&&16384!==(e.mode&61440))throw new T(54);if(!c&&(d=e?40960===(e.mode&61440)?32:16384===(e.mode&61440)&&("r"!==Lb(b)||b&512)?31:Ib(e,Lb(b)):44))throw new T(d);if(b&512&&!c){d=e;d="string"==typeof d?W(d,{T:!0}).node:d;if(!d.h.s)throw new T(63);if(16384===(d.mode&61440))throw new T(31);if(32768!==(d.mode&61440))throw new T(28);if(c=Ib(d,"w"))throw new T(c);d.h.s(d,{size:0,
timestamp:Date.now()});}b&=-131713;e=Ob({node:e,path:Gb(e),flags:b,seekable:!0,position:0,l:e.l,pa:[],error:!1});e.l.open&&e.l.open(e);!g.logReadFiles||b&1||(Sb||(Sb={}),a in Sb||(Sb[a]=1));},Ub=()=>{T||(T=function(a,b){this.node=b;this.message="FS error";},T.prototype=Error(),T.prototype.constructor=T,[44].forEach(a=>{yb[a]=new T(a);yb[a].stack="<generic error, no stack>";}));},Vb,Wb=(a,b)=>{var c=0;a&&(c|=365);b&&(c|=146);return c},Z=(a,b,c)=>{a=lb("/dev/"+a);var d=Wb(!!b,!!c);Xb||(Xb=64);var e=Xb++<<
8|0;sb(e,{open:f=>{f.seekable=!1;},close:()=>{c&&c.buffer&&c.buffer.length&&c(10);},read:(f,h,m,p)=>{for(var q=0,n=0;n<p;n++){try{var r=b();}catch(C){throw new T(29);}if(void 0===r&&0===q)throw new T(6);if(null===r||void 0===r)break;q++;h[m+n]=r;}q&&(f.node.timestamp=Date.now());return q},write:(f,h,m,p)=>{for(var q=0;q<p;q++)try{c(h[m+q]);}catch(n){throw new T(29);}p&&(f.node.timestamp=Date.now());return q}});Qb(a,d,e);},Xb,X,Sb;
function Yb(a){if(!noExitRuntime){if(g.onExit)g.onExit(a);la=!0;}k(a,new ja(a));}function Jb(a,b,c,d){a||(a=this);this.parent=a;this.u=a.u;this.H=null;this.id=Db++;this.name=b;this.mode=c;this.h={};this.l={};this.rdev=d;}Object.defineProperties(Jb.prototype,{read:{get:function(){return 365===(this.mode&365)},set:function(a){a?this.mode|=365:this.mode&=-366;}},write:{get:function(){return 146===(this.mode&146)},set:function(a){a?this.mode|=146:this.mode&=-147;}}});Ub();V=Array(4096);Pb(U,"/");
Y("/tmp",16895,0);Y("/home",16895,0);Y("/home/web_user",16895,0);(()=>{Y("/dev",16895,0);sb(259,{read:()=>0,write:(b,c,d,e)=>e});Qb("/dev/null",259);rb(1280,ub);rb(1536,vb);Qb("/dev/tty",1280);Qb("/dev/tty1",1536);var a=ob();Z("random",a);Z("urandom",a);Y("/dev/shm",16895,0);Y("/dev/shm/tmp",16895,0);})();
(()=>{Y("/proc",16895,0);var a=Y("/proc/self",16895,0);Y("/proc/self/fd",16895,0);Pb({u:()=>{var b=xb(a,"fd",16895,73);b.h={lookup:(c,d)=>{var e=Cb[+d];if(!e)throw new T(8);c={parent:null,u:{Y:"fake"},h:{readlink:()=>e.path}};return c.parent=c}};return b}},"/proc/self/fd");})();var Q={__heap_base:Sa,__indirect_function_table:I,__memory_base:eb,__stack_pointer:fb,__table_base:gb,emscripten_asm_const_int:ib,emscripten_resize_heap:jb,memory:D};
(function(){function a(e,f){e=e.exports;e=Ya(e,1024);g.asm=e;f=Ja(f);f.B&&(z=f.B.concat(z));La(e);ua.unshift(g.asm.__wasm_call_ctors);ya.push(g.asm.__wasm_apply_data_relocs);Ca();}function b(e){a(e.instance,e.module);}function c(e){return Ga().then(function(f){return WebAssembly.instantiate(f,d)}).then(function(f){return f}).then(e,function(f){y("failed to asynchronously prepare wasm: "+f);B(f);})}var d={env:Q,wasi_snapshot_preview1:Q,"GOT.mem":new Proxy(Q,O),"GOT.func":new Proxy(Q,O)};Ba();if(g.instantiateWasm)try{return g.instantiateWasm(d,
a)}catch(e){return y("Module.instantiateWasm callback failed with error: "+e),!1}(function(){return A||"function"!=typeof WebAssembly.instantiateStreaming||Da()||M.startsWith("file://")||t||"function"!=typeof fetch?c(b):fetch(M,{credentials:"same-origin"}).then(function(e){return WebAssembly.instantiateStreaming(e,d).then(b,function(f){y("wasm streaming compile failed: "+f);y("falling back to ArrayBuffer instantiation");return c(b)})})})().catch(ba);return {}})();
g.___wasm_call_ctors=function(){return (g.___wasm_call_ctors=g.asm.__wasm_call_ctors).apply(null,arguments)};g.___wasm_apply_data_relocs=function(){return (g.___wasm_apply_data_relocs=g.asm.__wasm_apply_data_relocs).apply(null,arguments)};g._random_number_in_range=function(){return (g._random_number_in_range=g.asm.random_number_in_range).apply(null,arguments)};
var Ua=g._malloc=function(){return (Ua=g._malloc=g.asm.malloc).apply(null,arguments)},Ra=g._setThrew=function(){return (Ra=g._setThrew=g.asm.setThrew).apply(null,arguments)},Pa=g.stackSave=function(){return (Pa=g.stackSave=g.asm.stackSave).apply(null,arguments)},Qa=g.stackRestore=function(){return (Qa=g.stackRestore=g.asm.stackRestore).apply(null,arguments)},Zb=g.stackAlloc=function(){return (Zb=g.stackAlloc=g.asm.stackAlloc).apply(null,arguments)},$b;L=function ac(){$b||bc();$b||(L=ac);};
function cc(a){var b=g._main;if(b){a=a||[];a.unshift(ea);var c=a.length,d=Zb(4*(c+1)),e=d>>2;a.forEach(h=>{var m=H,p=e++,q=oa(h)+1,n=Zb(q);na(h,G,n,q);m[p]=n;});H[e]=0;try{var f=b(c,d);Yb(f);}catch(h){h instanceof ja||"unwind"==h||k(1,h);}}}var dc=!1;
function bc(){function a(){if(!$b&&($b=!0,g.calledRun=!0,!la)){J=!0;P(ya);g.noFSInit||Vb||(Vb=!0,Ub(),g.stdin=g.stdin,g.stdout=g.stdout,g.stderr=g.stderr,g.stdin?Z("stdin",g.stdin):Rb("/dev/tty","/dev/stdin"),g.stdout?Z("stdout",null,g.stdout):Rb("/dev/tty","/dev/stdout"),g.stderr?Z("stderr",null,g.stderr):Rb("/dev/tty1","/dev/stderr"),Tb("/dev/stdin",0),Tb("/dev/stdout",1),Tb("/dev/stderr",1));Eb=!1;P(ua);P(va);aa(g);if(g.onRuntimeInitialized)g.onRuntimeInitialized();ec&&cc(b);if(g.postRun)for("function"==
typeof g.postRun&&(g.postRun=[g.postRun]);g.postRun.length;){var c=g.postRun.shift();xa.unshift(c);}P(xa);}}var b=b||da;if(!(0<K)){if(!dc&&(db(),dc=!0,0<K))return;if(g.preRun)for("function"==typeof g.preRun&&(g.preRun=[g.preRun]);g.preRun.length;)za();P(ta);0<K||(g.setStatus?(g.setStatus("Running..."),setTimeout(function(){setTimeout(function(){g.setStatus("");},1);a();},1)):a());}}if(g.preInit)for("function"==typeof g.preInit&&(g.preInit=[g.preInit]);0<g.preInit.length;)g.preInit.pop()();var ec=!0;
g.noInitialRun&&(ec=!1);bc();


  return utilsMethodsModule.ready
}
);
})();

// Copyright (C) 2022 Deliberative Technologies P.C.
const randomNumberInRange = async (min, max, 
// wasm?: WebAssembly.Exports,
module) => {
    if (module)
        return module._random_number_in_range(min, max);
    const wasmMemory = memory$2.randomNumberInRangeMemory(min, max);
    const utilsModule = await utilsMethodsModule({ wasmMemory });
    return utilsModule._random_number_in_range(min, max);
};

// Copyright (C) 2022 Deliberative Technologies P.C.
/** Fisher-Yates Shuffle */
const arrayRandomShuffle = async (array) => {
    const n = array.length;
    // If array has <2 items, there is nothing to do
    if (n < 2)
        return array;
    const shuffled = [...array];
    const wasmMemory = memory$2.randomNumberInRangeMemory(0, n);
    const utilsModule = await utilsMethodsModule({ wasmMemory });
    for (let i = n - 1; i > 0; i--) {
        const j = await randomNumberInRange(0, i + 1, utilsModule);
        const temp = shuffled[i];
        shuffled[i] = shuffled[j];
        shuffled[j] = temp;
    }
    return shuffled;
};

// Copyright (C) 2022 Deliberative Technologies P.C.
/** Random slice of array */
const arrayRandomSubset = async (array, elements) => {
    const n = array.length;
    // Sanity check
    if (n < elements || n < 2)
        throw new Error("Not enough elements in the array");
    const shuffled = await arrayRandomShuffle(array);
    return shuffled.slice(0, elements);
};

// Copyright (C) 2022 Deliberative Technologies P.C.
var utils = {
    randomBytes,
    randomNumberInRange,
    arrayRandomShuffle,
    arrayRandomSubset,
    memory: memory$2,
};

// Copyright (C) 2022 Deliberative Technologies P.C.
const dcrypto = {
    randomBytes: utils.randomBytes,
    randomNumberInRange: utils.randomNumberInRange,
    arrayRandomShuffle: utils.arrayRandomShuffle,
    arrayRandomSubset: utils.arrayRandomSubset,
    loadUtilsMemory: {
        randomBytes: utils.memory.randomBytesMemory,
        randomNumberInRange: utils.memory.randomNumberInRangeMemory,
    },
    loadUtilsModule: utilsMethodsModule,
    keyPair: asymmetric.keyPair.newKeyPair,
    keyPairFromSeed: asymmetric.keyPair.keyPairFromSeed,
    keyPairFromSecretKey: asymmetric.keyPair.keyPairFromSecretKey,
    sign: asymmetric.sign,
    verify: asymmetric.verify,
    encrypt: asymmetric.encrypt,
    decrypt: asymmetric.decrypt,
    generateMnemonic: mnemonic.generateMnemonic,
    validateMnemonic: mnemonic.validateMnemonic,
    keypairFromMnemonic: mnemonic.keyPairFromMnemonic,
    loadAsymmetricMemory: {
        newKeyPair: asymmetric.memory.newKeyPairMemory,
        keyPairFromSeed: asymmetric.memory.keyPairFromSeedMemory,
        keyPairFromSecretKey: asymmetric.memory.keyPairFromSecretKeyMemory,
        sign: asymmetric.memory.signMemory,
        verify: asymmetric.memory.verifyMemory,
        encrypt: asymmetric.memory.encryptMemory,
        decrypt: asymmetric.memory.decryptMemory,
    },
    loadLibsodiumModule: libsodiumMethodsModule,
    sha512: hash.sha512,
    getMerkleRoot: hash.getMerkleRoot,
    loadHashMemory: {
        sha512: hash.memory.sha512Memory,
        merkleRoot: hash.memory.merkleRootMemory,
    },
    loadHashModule: libsodiumMethodsModule,
    splitSecret: shamir.splitSecret,
    restoreSecret: shamir.restoreSecret,
    loadShamirMemory: {
        splitSecret: shamir.memory.splitSecretMemory,
        restoreSecret: shamir.memory.restoreSecretMemory,
    },
    loadShamirModule: shamirMethodsModule,
};

exports["default"] = dcrypto;
//# sourceMappingURL=index.cjs.js.map
