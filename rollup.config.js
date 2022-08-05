import commonjs from "@rollup/plugin-commonjs";
import resolve from "@rollup/plugin-node-resolve";
import babel from "@rollup/plugin-babel";
import replace from "@rollup/plugin-replace";
import typescript from "@rollup/plugin-typescript";
import { wasm } from "@rollup/plugin-wasm";
import json from "@rollup/plugin-json";
import { terser } from "rollup-plugin-terser";
import gzipPlugin from "rollup-plugin-gzip";
import analyzer from "rollup-plugin-analyzer";

import pkg from "./package.json";

const production = !process.env.ROLLUP_WATCH;
const dir = "lib";
const input = "src/index.ts";

const plugins = [
  resolve({
    browser: true,
    preferBuiltins: false,
  }),

  commonjs(),

  replace({
    preventAssignment: true,
    "process.env.NODE_ENV": JSON.stringify(production),
  }),

  wasm(),

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
      "node_modules/bip39/wordlists/czech.json",
      "node_modules/bip39/wordlists/chinese_simplified.json",
      "node_modules/bip39/wordlists/chinese_traditional.json",
      "node_modules/bip39/wordlists/korean.json",
      "node_modules/bip39/wordlists/french.json",
      "node_modules/bip39/wordlists/italian.json",
      "node_modules/bip39/wordlists/spanish.json",
      "node_modules/bip39/wordlists/japanese.json",
      "node_modules/bip39/wordlists/portuguese.json",
    ],
    outDir: `${dir}`,
  }),

  analyzer(),
];

export default [
  // UMD
  {
    input,
    plugins: [
      ...plugins,
      babel({
        babelHelpers: "bundled",
      }),
      production &&
        terser({
          compress: true,
          mangle: true,
        }),

      production && gzipPlugin(),
    ],
    output: {
      name: "dcrypto",
      file: pkg.browser,
      format: "umd",
      esModule: false,
      exports: "named",
      sourcemap: true,
    },
  },

  // ESM and CJS
  {
    input,
    plugins,
    output: [
      {
        file: pkg.module,
        format: "es",
        exports: "named",
        sourcemap: true,
      },
      {
        file: pkg.main,
        format: "cjs",
        exports: "named",
        sourcemap: true,
      },
    ],
  },
];
