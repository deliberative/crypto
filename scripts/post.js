const fs = require("fs");
const path = require("path");

const esmPath = path.join(process.cwd(), "lib", "index.mjs");
const cjsPath = path.join(process.cwd(), "lib", "index.cjs");

const esmBundle = fs.readFileSync(esmPath);
fs.writeFileSync(
  esmPath,
  `\
import \{ dirname \} from \"path\"; \
import \{ createRequire \} from \"module\"; \
globalThis.__dirname = dirname(import.meta.url).substring(7); \
globalThis.require = createRequire(import.meta.url); \
${esmBundle}`,
);

const cjsBundle = fs.readFileSync(cjsPath);
fs.writeFileSync(
  cjsPath,
  `\
${cjsBundle}\
module.exports = dcrypto;
`,
);
