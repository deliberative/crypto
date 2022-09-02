const fs = require("fs");
const path = require("path");

const esmPath = path.join(process.cwd(), "lib", "index.mjs");

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
