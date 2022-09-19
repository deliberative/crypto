const fs = require("fs");
const path = require("path");

const esmPath = path.join(process.cwd(), "lib", "index.node.mjs");

const esmRequire = `\
import crypto from \"crypto\";\n\
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
