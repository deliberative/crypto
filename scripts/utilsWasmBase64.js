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
  distPath,
  libsodiumIncludePath,
  libsodiumIncludePrivatePath,
  licenseApache,
  emcc,
} from "./utils.js";

const methodsPath = path.join(srcPath, "c", "utils_methods.c");
const wasmPath = path.join(buildPath, "utilsMethodsModule.js");
const base64Path = path.join(distPath, "utilsMethods.ts");
const typesPath = path.join(
  process.cwd(),
  "scripts",
  "utilsMethodsModule.d.ts",
);
const types = fs.readFileSync(typesPath);
fs.writeFileSync(wasmPath.replace("le.js", "le.d.ts"), types);

exec(
  `\
${emcc} \
-s EXPORTED_FUNCTIONS=_random_number_in_range \
-s EXPORT_NAME=utilsMethodsModule \
--closure 1 \
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
      `stdout: Successfully compiled utils methods wasm module! ${stdout}`,
    );

    const wasmSrc = fs.readFileSync(wasmPath);
    const wasmBuffer = Buffer.from(wasmSrc, "binary").toString("base64");
    const data = `
${licenseApache}

const utilsMethods = '${wasmBuffer}';

export default utilsMethods;`;
    fs.writeFileSync(base64Path, data);
  },
);
