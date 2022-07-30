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

const fs = require('fs');
const { exec } = require('child_process');

const {
  libsodiumIncludePath,
  libsodiumIncludePrivatePath,
  libraryPath,
  licenseApache,
  licenseAGPL3,
  emcc,
} = require('./utils');

function compileWithEmcc(
  methodsPath,
  wasmPath,
  tsPath,
  name,
  exportedName,
  licenseName,
) {
  exec(
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

      console.log(
        `stdout: Successfully compiled ${name} method wasm module! ${stdout}`,
      );

      const wasmSrc = fs.readFileSync(wasmPath);
      const wasmBuffer = Buffer.from(wasmSrc, 'binary').toString('base64');
      const data = `
${licenseName === 'AGPL3' ? licenseAGPL3 : licenseApache}

const ${exportedName} = '${wasmBuffer}';

export default ${exportedName};`;
      fs.writeFileSync(tsPath, data);
    },
  );
}

module.exports = {
  compileWithEmcc,
};
