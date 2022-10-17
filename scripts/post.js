const fs = require("fs");
const path = require("path");
const { minify } = require("terser");

const esmPath = path.join(process.cwd(), "lib", "index.node.mjs");

const esmRequire = `\
import crypto from \"crypto\";\n\
import path from \"path\";\n\
import {fileURLToPath} from \"url\";\n\
const __filename = fileURLToPath(import.meta.url);\n\
const __dirname = path.dirname(__filename);\
`;

const esmBundle = fs.readFileSync(esmPath, "utf8");
fs.writeFileSync(
  esmPath,
  `\
${esmRequire} \
${esmBundle
  .replace('var crypto = require("crypto");', "")
  .replace('var crypto=require("crypto");', "")}`,
);

const browserPath = path.join(process.cwd(), "lib", "index.min.js");
const unminified = fs.readFileSync(browserPath, "utf8");
minify(unminified, {
  ecma: 2020,
  mangle: { toplevel: true },
  compress: {
    module: true,
    toplevel: true,
    unsafe_arrows: true,
    drop_console: true,
    drop_debugger: true,
  },
}).then((minified) => {
  fs.writeFileSync(browserPath, minified.code);
});
