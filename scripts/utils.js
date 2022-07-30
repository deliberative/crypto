const path = require("path");

const srcPath = path.join(__dirname, "..", "src");
const buildPath = path.join(__dirname, "..", "build");
const distPath = path.join(__dirname, "..", "dist");

const libsodiumIncludePath = path.join(
  __dirname,
  "..",
  "libsodium",
  "src",
  "libsodium",
  "include",
  "sodium",
);

const libsodiumIncludePrivatePath = path.join(
  __dirname,
  "..",
  "libsodium",
  "src",
  "libsodium",
  "include",
  "sodium",
  "private",
);

const libraryPath = path.join(__dirname, "..", "src", "emscriptenLibrary.js");

const licenseApache = `
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
`;

const emcc = `emcc \
--no-entry \
-O3 \
-IMPORTED_MEMORY \
-s RESERVED_FUNCTION_POINTERS=8 \
-s ASSERTIONS=0 \
-s AGGRESSIVE_VARIABLE_ELIMINATION=1 \
-s ALIASING_FUNCTION_POINTERS=1 \
-s ELIMINATE_DUPLICATE_FUNCTIONS=1 \
-s DISABLE_EXCEPTION_CATCHING=1 \
-s ELIMINATE_DUPLICATE_FUNCTIONS=1 \
-s ERROR_ON_UNDEFINED_SYMBOLS=0 \
-s FILESYSTEM=0 \
`;

const clangOpts = `--target=wasm32-unknown-unknown-wasm \
-std=c11 \
-flto \
-Wl,--lto-O3 \
-O3 \
-nostdlib \
-Wl,--no-entry \
-fno-builtin \
-Wl,--export-all \
-Wl,--allow-undefined \
`;

module.exports = {
  srcPath,
  buildPath,
  distPath,
  libsodiumIncludePath,
  libsodiumIncludePrivatePath,
  libraryPath,
  licenseApache,
  emcc,
  clangOpts,
};
