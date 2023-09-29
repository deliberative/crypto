import commonjs from "@rollup/plugin-commonjs";
import json from "@rollup/plugin-json";
import resolve from "@rollup/plugin-node-resolve";
import replace from "@rollup/plugin-replace";
import typescript from "@rollup/plugin-typescript";
import url from "@rollup/plugin-url";
// import { terser } from "rollup-plugin-terser";
// import analyzer from "rollup-plugin-analyzer";
import copy from "rollup-plugin-copy";
import fs from "node:fs";

import pkg from "./package.json" assert { type: "json" };

const production = process.env.NODE_ENV === "production";
const browser = process.env.NODE_OR_BROWSER === "browser";
const dir = "lib";
const input = "src/index.ts";

const plugins = [
  replace({
    preventAssignment: true,
    "process.env.NODE_ENV": JSON.stringify(production),
  }),

  resolve({
    // jsnext: true,
    // main: true,
    // module: true,
    browser,
    preferBuiltins: !browser,
  }),

  commonjs(),

  url(),

  json({
    compact: true,
    preferConst: true,
  }),

  typescript({
    sourceMap: true,
    inlineSources: !production,
    declarationMap: true,
    exclude: [
      "__tests__",
      "__tests__/*.test.ts",
      "__specs__",
      "__specs__/*.spec.ts",
      "playwright*",
      "rollup*",
    ],
    outDir: `${dir}`,
  }),

  fs.existsSync("src/c/build/dcryptoMethodsModule.wasm") &&
    copy({
      targets: [
        {
          src: "src/c/build/dcryptoMethodsModule.wasm",
          dest: `${dir}`,
        },
      ],
    }),

  // analyzer(),
];

export default [
  // UMD
  {
    input,
    plugins,
    output: {
      name: "dcrypto",
      file: pkg.browser,
      format: "umd",
      esModule: false,
      interop: "default",
      extend: true,
      sourcemap: true,
    },
  },

  // ESM and CJS
  {
    input,
    plugins,
    external: ["module"],
    output: browser
      ? [
          {
            file: pkg.module,
            format: "es",
            esModule: true,
            interop: "esModule",
            exports: "named",
            sourcemap: true,
          },
          {
            file: pkg.main,
            format: "cjs",
            esModule: false,
            interop: "defaultOnly",
            exports: "default",
            sourcemap: true,
          },
        ]
      : [
          {
            file: pkg.module.replace(".mjs", ".node.mjs"),
            format: "es",
            esModule: true,
            interop: "esModule",
            exports: "named",
            sourcemap: true,
          },
          {
            file: pkg.main.replace(".cjs", ".node.cjs"),
            format: "cjs",
            esModule: false,
            interop: "defaultOnly",
            exports: "default",
            sourcemap: true,
          },
        ],
  },
];
