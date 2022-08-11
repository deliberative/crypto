import path from "path";

export const srcPath = path.join(process.cwd(), "src");
export const buildPath = path.join(process.cwd(), "build");
export const distPath = path.join(process.cwd(), "dist");

export const libsodiumIncludePath = path.join(
  process.cwd(),
  "libsodium",
  "src",
  "libsodium",
  "include",
  "sodium",
);

export const libsodiumIncludePrivatePath = path.join(
  process.cwd(),
  "libsodium",
  "src",
  "libsodium",
  "include",
  "sodium",
  "private",
);

export const libraryPath = path.join(
  process.cwd(),
  "src",
  "emscriptenLibrary.js",
);

export const licenseApache = `
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

const testing = ``;
// const testing = `\
// -g3 \
// -gsource-map \
// -s ASSERTIONS=2 \
// -s LOAD_SOURCE_MAP=1 \
// -s ABORT_ON_WASM_EXCEPTIONS=1 \
// `;
// const testing = `\
// -g3 \
// --profiling \
// --memoryprofiler \
// -gsource-map \
// -s ASSERTIONS=2 \
// -fsanitize=address \
// -s RUNTIME_LOGGING=1 \
// -s RUNTIME_DEBUG=1 \
// -s STACK_OVERFLOW_CHECK=2 \
// -s LOAD_SOURCE_MAP=1 \
// -s ABORT_ON_WASM_EXCEPTIONS=1 \
// `;
// const testing = `\
// -g3 \
// --profiling \
// --memoryprofiler \
// -gsource-map \
// -fsanitize=undefined \
// -s ASSERTIONS=2 \
// -s RUNTIME_LOGGING=1 \
// -s RUNTIME_DEBUG=1 \
// -s STACK_OVERFLOW_CHECK=2 \
// -s SAFE_HEAP=2 \
// -s LOAD_SOURCE_MAP=1 \
// -s ABORT_ON_WASM_EXCEPTIONS=1 \
// `;

const withJS = ` \
-s WASM=1 \
-s MODULARIZE=1 \
-s MAIN_MODULE=2 \
-s STRICT_JS=1 \
-s EXPORT_ES6=1 \
-s USE_ES6_IMPORT_META=0 \
-s POLYFILL=0 \
`;

const memory = `\
-s IMPORTED_MEMORY=1 \
-s ALLOW_MEMORY_GROWTH=1 \
-s MEMORY_GROWTH_LINEAR_STEP=64kb \
-s INITIAL_MEMORY=2mb \
-s MAXIMUM_MEMORY=100mb \
-s TOTAL_STACK=1mb \
`;

export const emcc = `\
emcc \
-O3 \
-flto \
--no-entry \
-s STRICT \
${testing} \
${memory} \
-s LLD_REPORT_UNDEFINED \
-s NODEJS_CATCH_EXIT=0 \
-s NODEJS_CATCH_REJECTION=0 \
${withJS} \
`;

export const clangOpts = `\
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
