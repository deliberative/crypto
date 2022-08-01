import commonjs from "@rollup/plugin-commonjs";
import resolve from "@rollup/plugin-node-resolve";
import replace from "@rollup/plugin-replace";
import typescript from "@rollup/plugin-typescript";
import { wasm } from "@rollup/plugin-wasm";
import json from "@rollup/plugin-json";
import { terser } from "rollup-plugin-terser";
import analyzer from "rollup-plugin-analyzer";

const production = !process.env.ROLLUP_WATCH;

export default {
  input: "src/index.ts",
  output: {
    sourcemap: !production,
    format: "es",
    name: "deliberative",
    dir: production ? "lib" : "build",
    // manualChunks: (moduleName) => {
    //   // Every module whose name includes `node_modules` should be in vendor:
    //   if (moduleName.includes('node_modules')) {
    //     return 'vendor';
    //   }
    //   // Every other module will be in the chunk based on its entry point!
    // },
  },
  plugins: [
    replace({
      preventAssignment: true,
      "process.env.NODE_ENV": JSON.stringify(production),
    }),

    wasm(),

    json({
      compact: true,
      exclude: [
        "./node_modules/bip39/wordlists/czech.json",
        "./node_modules/bip39/wordlists/chinese_simplified.json",
        "./node_modules/bip39/wordlists/chinese_traditional.json",
        "./node_modules/bip39/wordlists/korean.json",
        "./node_modules/bip39/wordlists/french.json",
        "./node_modules/bip39/wordlists/italian.json",
        "./node_modules/bip39/wordlists/spanish.json",
        "./node_modules/bip39/wordlists/japanese.json",
        "./node_modules/bip39/wordlists/portuguese.json",
      ],
      preferConst: true,
    }),

    typescript({
      sourceMap: !production,
      inlineSources: !production,
      declarationMap: !production,
      exclude: ["__tests__", "__tests__/*.test.ts"],
      outDir: production ? "lib" : "build",
    }),

    // If you have external dependencies installed from
    // npm, you'll most likely need these plugins. In
    // some cases you'll need additional configuration -
    // consult the documentation for details:
    // https://github.com/rollup/plugins/tree/master/packages/commonjs
    resolve({
      browser: true,
      preferBuiltins: false,
    }),

    commonjs(),

    analyzer(),

    // If we're building for production (npm run build
    // instead of npm run dev), minify
    production &&
      terser({
        compress: production,
        mangle: production,
      }),
  ],
  watch: {
    clearScreen: false,
  },
};
