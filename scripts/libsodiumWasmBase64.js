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

import fs from "fs";
import path from "path";
import { exec } from "child_process";

import {
  srcPath,
  buildPath,
  libsodiumIncludePath,
  libsodiumIncludePrivatePath,
  emcc,
} from "./utils.js";

const methodsPath = path.join(srcPath, "c", "libsodium_methods.c");
const wasmPath = path.join(buildPath, "libsodiumMethodsModule.js");
const typesPath = path.join(
  process.cwd(),
  "scripts",
  "libsodiumMethodsModule.d.ts",
);
const types = fs.readFileSync(typesPath);
fs.writeFileSync(wasmPath.replace("le.js", "le.d.ts"), types);

// -s INITIAL_MEMORY=128kb \ 2 pages
// -s TOTAL_STACK=65kb \ 2 pages

exec(
  `\
${emcc} \
-s EXPORTED_FUNCTIONS=\
_sha512,\
_random_bytes,\
_new_keypair,\
_keypair_from_seed,\
_keypair_from_secret_key,\
_sign_data,\
_verify_data,\
_encrypt_data,\
_decrypt_data \
-s EXPORT_NAME=libsodiumMethodsModule \
-I${libsodiumIncludePath} \
-I${libsodiumIncludePrivatePath} \
-o ${wasmPath} \
${methodsPath}`,
  (error, stdout, stderr) => {
    if (error) {
      console.error(error.message);
      return;
    }

    if (stderr) {
      console.error(`stderr: ${stderr}`);
    }

    console.log(
      `stdout: Successfully compiled libsodium methods wasm module! ${stdout}`,
    );
  },
);
