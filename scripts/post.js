const fs = require("fs");
const path = require("path");

const postPath = path.join(process.cwd(), "scripts", "pre.js");
const esmPath = path.join(process.cwd(), "lib", "index.mjs");

const additional = fs.readFileSync(postPath);
let bundle = fs.readFileSync(esmPath);
fs.writeFileSync(esmPath, additional + "\n" + bundle);
