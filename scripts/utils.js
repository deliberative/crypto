const path = require("path");

const srcPath = path.join(process.cwd(), "src");
const buildPath = path.join(process.cwd(), "build");
const distPath = path.join(process.cwd(), "dist");

const libsodiumIncludePath = path.join(
  process.cwd(),
  "libsodium",
  "src",
  "libsodium",
  "include",
  "sodium",
);

const libsodiumIncludePrivatePath = path.join(
  process.cwd(),
  "libsodium",
  "src",
  "libsodium",
  "include",
  "sodium",
  "private",
);

const libraryPath = path.join(process.cwd(), "src", "emscriptenLibrary.js");

const licenseApache = `
// Copyright (C) 2023 Deliberative Technologies P.C.
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

const withJS = ` \
-s WASM=1 \
-s MODULARIZE=1 \
-s MAIN_MODULE=2 \
-s POLYFILL=0 \
-s BUILD_AS_WORKER=1 \
`;

const browser = process.env.NODE_OR_BROWSER === "browser" ? ` \
-s SINGLE_FILE=1 \
-s ENVIRONMENT=\'webview\' \
` : "";

const memory = `\
-s IMPORTED_MEMORY=1 \
-s ALLOW_MEMORY_GROWTH=1 \
-s INITIAL_MEMORY=${process.env.NODE_ENV === "production" ? "256kb" : "10mb" } \
-s STACK_SIZE=${process.env.NODE_ENV === "production" ? "128kb" : "5mb" } \
-s MALLOC=emmalloc-memvalidate \
`;

const emcc = `\
emcc \
--no-entry \
-s STRICT \
${memory} \
${withJS} \
${browser} \
-s NODEJS_CATCH_EXIT=0 \
-s NODEJS_CATCH_REJECTION=0 \
`;

const clangOpts = `\
--target=wasm32-unknown-unknown-wasm \
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
  emcc,
  srcPath,
  buildPath,
  distPath,
  libsodiumIncludePath,
  libsodiumIncludePrivatePath,
  libraryPath,
  licenseApache,
  clangOpts,
};
