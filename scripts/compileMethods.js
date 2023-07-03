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

const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

const {
  srcPath,
  libsodiumIncludePath,
  libsodiumIncludePrivatePath,
  emcc,
} = require("./utils.js");

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

const testing =
  process.env.NODE_ENV === "production"
    ? `\
-flto \
-Os \
-s FILESYSTEM=0 \
-s ASSERTIONS=0 \
-s INVOKE_RUN=0 \
-s USE_CLOSURE_COMPILER=1 \
-s MALLOC=emmalloc \
`
    : `\
-O0 \
-g3 \
--profiling \
-gsource-map \
-fsanitize=undefined \
-s ASSERTIONS=2 \
-s RUNTIME_LOGGING=1 \
-s RUNTIME_DEBUG=1 \
-s SAFE_HEAP=2 \
-s STACK_OVERFLOW_CHECK=2 \
-s EXIT_RUNTIME=1 \
`;

execSync(
  `\
${emcc} \
${testing} \
-s EXPORTED_FUNCTIONS=\
_malloc,\
_free \
-s EXPORT_NAME=dcryptoMethodsModule \
-I${libsodiumIncludePath} \
-I${libsodiumIncludePrivatePath} \
-o ${wasmPath} \
${methodsPath}`,
  { stdio: "inherit" },
);

let content = fs.readFileSync(wasmPath, "utf8");
fs.writeFileSync(
  wasmPath,
  "'use strict'" + content.replace('"use strict"', ""),
);

console.log("Successfully compiled dcrypto c methods to Wasm.");
