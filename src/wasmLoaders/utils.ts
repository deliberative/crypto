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

// import * as nacl from 'tweetnacl';

import { randombytes_js } from "./randombytes";

import isBrowser from "../utils/isBrowser";

import utilsMethods from "../../dist/utilsMethods";

const loadUtils = async (memoryLen: number) => {
  let pages = 0; // 1 page is 64 kb or 64000 bytes
  if (memoryLen) {
    if (memoryLen <= 64000) {
      pages = 1;
    } else {
      // If modulo > 0 then we add one more page to the memory
      pages = Math.ceil(memoryLen / 64000);
    }
  }

  const memory = new WebAssembly.Memory({ initial: pages, maximum: pages + 1 });

  let buf: Uint8Array;
  if (isBrowser()) {
    const raw = window.atob(utilsMethods);
    const rawLength = raw.length;
    buf = new Uint8Array(new ArrayBuffer(rawLength));
    for (let i = 0; i < rawLength; i++) {
      buf[i] = raw.charCodeAt(i);
    }
  } else {
    buf = Buffer.from(utilsMethods, "base64");
  }

  const module = new WebAssembly.Module(buf);
  const wasm = memory
    ? await WebAssembly.instantiate(module, {
        env: {
          abortStackOverflow: () => {
            throw new Error("Stack overflow");
          },
          table: new WebAssembly.Table({
            initial: 0,
            maximum: 0,
            element: "anyfunc",
          }),
          tableBase: 0,
          memory,
          memoryBase: 1024,
          STACKTOP: 0,
          STACK_MAX: memory.buffer.byteLength,

          randombytes_js: (): number => {
            return randombytes_js();
          },
        },
      })
    : await WebAssembly.instantiate(module);

  return wasm.exports;
};

export default loadUtils;
