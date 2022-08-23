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
  libsodiumIncludePath,
  libsodiumIncludePrivatePath,
} = require("./utils.js");

const testFilename = "libsodium_methods";
const testPath = path.join(process.cwd(), "examples", "c", `${testFilename}.c`);
const outputPath = testPath.replace(`${testFilename}.c`, `${testFilename}.o`);
const valgrindReportPath = outputPath.replace(
  `${testFilename}.o`,
  `${testFilename}-valgrind-report.txt`,
);

if (fs.existsSync(outputPath)) fs.rmSync(outputPath);
if (fs.existsSync(valgrindReportPath)) fs.rmSync(valgrindReportPath);

exec(
  `clang -Werror -ggdb -g -fstandalone-debug -fsanitize=address -Og -lm \
-I${libsodiumIncludePath} \
-I${libsodiumIncludePrivatePath} \
-o ${outputPath} \
${testPath}`,
  (error, stdout, stderr) => {
    if (error) {
      console.error(error.message);
      return;
    } else if (stderr) {
      console.error(`stderr: ${stderr}`);
      return;
    }

    console.log(
      `stdout: Successfully compiled ${testFilename} c test! ${stdout}`,
    );

    exec(
      `valgrind \
--log-file=\"${valgrindReportPath}\" \
--leak-check=full \
--show-leak-kinds=all \
--track-origins=yes \
--verbose \
--dsymutil=yes \
--trace-children=yes \
-v \
${outputPath}`,
      (err, out, derr) => {
        if (err) {
          console.error(err.message);
          return;
        } else if (derr) {
          console.error(`stderr: ${err}`);
          return;
        }

        console.log(
          `stdout: Successfully run Valgrind on ${outputPath} ${out}`,
        );
      },
    );
  },
);
