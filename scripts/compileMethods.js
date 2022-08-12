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
import { execSync } from "child_process";

import {
  srcPath,
  libsodiumIncludePath,
  libsodiumIncludePrivatePath,
  emcc,
} from "./utils.js";

const basePath = path.join(srcPath, "c");
const buildPath = path.join(basePath, "build");
if (fs.existsSync(buildPath))
  fs.rmSync(buildPath, { recursive: true, force: true });
fs.mkdirSync(buildPath);

const methodsPath = path.join(basePath, "dcrypto.c");
const wasmPath = path.join(buildPath, "dcryptoMethodsModule.js");

const typesPath = path.join(
  process.cwd(),
  "scripts",
  "dcryptoMethodsModule.d.ts",
);
const types = fs.readFileSync(typesPath);
fs.writeFileSync(wasmPath.replace("le.js", "le.d.ts"), types);

execSync(
  `\
${emcc} \
-s EXPORTED_FUNCTIONS=\
_sha512,\
_random_bytes,\
_argon2,\
_new_keypair,\
_keypair_from_seed,\
_keypair_from_secret_key,\
_sign_data,\
_verify_data,\
_encrypt_data,\
_decrypt_data,\
_random_number_in_range,\
_split_secret,\
_restore_secret \
-s EXPORT_NAME=dcryptoMethodsModule \
-I${libsodiumIncludePath} \
-I${libsodiumIncludePrivatePath} \
-o ${wasmPath} \
${methodsPath}`,
  { stdio: "inherit" },
);

console.log("Successfully compiled dcrypto c methods to Wasm.");
