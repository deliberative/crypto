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
const { exec } = require("child_process");

const {
  srcPath,
  buildPath,
  distPath,
  libsodiumIncludePath,
  libsodiumIncludePrivatePath,
  libraryPath,
  licenseApache,
  emcc,
  // clangOpts,
} = require("./utils");

const methodsPath = path.join(srcPath, "c", "utils_methods.c");
const wasmPath = path.join(buildPath, "utils_methods.wasm");
const base64Path = path.join(distPath, "utilsMethods.ts");

exec(
  //   `clang \
  // ${methodsPath} \
  // ${clangOpts} \
  // --output ${wasmPath}`,
  `${emcc} \
-I${libsodiumIncludePath} \
-I${libsodiumIncludePrivatePath} \
--js-library ${libraryPath} \
-o ${wasmPath} \
${methodsPath}`,
  (error, stdout, stderr) => {
    if (error) {
      console.error(error.message);
      return;
    } else if (stderr) {
      console.error(`stderr: ${stderr}`);
      return;
    }

    console.log(`stdout: Successfully compiled Utils wasm module! ${stdout}`);

    const wasmSrc = fs.readFileSync(wasmPath);
    const wasmBuffer = Buffer.from(wasmSrc, "binary").toString("base64");
    const data = `
${licenseApache}

const utilsMethods = '${wasmBuffer}';

export default utilsMethods;`;
    fs.writeFileSync(base64Path, data);
  },
);
