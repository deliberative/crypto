const fs = require("fs");
const path = require("path");

const esmPath = path.join(process.cwd(), "lib", "index.mjs");
const cjsPath = path.join(process.cwd(), "lib", "index.cjs");
// const umdPath = path.join(process.cwd(), "lib", "index.min.js");

const esmBundle = fs.readFileSync(esmPath);
fs.writeFileSync(
  esmPath,
  `\
import \{ dirname \} from \"path\";\n\
import \{ createRequire \} from \"module\";\n\
globalThis.__dirname = dirname(import.meta.url).substring(7);\n\
globalThis.require = createRequire(import.meta.url);\n\
${esmBundle}`,
);

let cjsBundle = fs.readFileSync(cjsPath, "utf8");
fs.writeFileSync(
  cjsPath,
  cjsBundle.replace(
    "//# sourceMappingURL=index.cjs.map",
    "module.exports = dcrypto;\n//# sourceMappingURL=index.cjs.map",
  ),
);

// const umdBundle = fs.readFileSync(umdPath);
// fs.writeFileSync(
//   umdPath,
//   `${umdBundle}\n\
// export default dcrypto;\
// `,
// );
