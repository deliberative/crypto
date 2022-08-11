import babel from "@rollup/plugin-babel";
import commonjs from "@rollup/plugin-commonjs";
import json from "@rollup/plugin-json";
import resolve from "@rollup/plugin-node-resolve";
import replace from "@rollup/plugin-replace";
import typescript from "@rollup/plugin-typescript";
import { wasm } from "@rollup/plugin-wasm";
import { terser } from "rollup-plugin-terser";
import gzipPlugin from "rollup-plugin-gzip";
import analyzer from "rollup-plugin-analyzer";

import pkg from "./package.json";

const production = !process.env.ROLLUP_WATCH;
const dir = "lib";
const input = "src/index.ts";

const plugins = [
  replace({
    preventAssignment: true,
    "process.env.NODE_ENV": JSON.stringify(production),
  }),

  resolve({
    browser: true,
    preferBuiltins: false,
  }),

  commonjs(),

  wasm(),

  json({
    compact: true,
    preferConst: true,
  }),

  typescript({
    sourceMap: true,
    inlineSources: !production,
    declarationMap: true,
    exclude: ["__tests__", "__tests__/*.test.ts"],
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

      terser({
        compress: true,
        mangle: true,
      }),

      gzipPlugin(),
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
