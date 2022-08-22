import fs from "fs";
import path from "path";

const postPath = path.join(process.cwd(), "scripts", "pre.js");
const esmPath = path.join(process.cwd(), "lib", "index.esm.js");

const additional = fs.readFileSync(postPath);
let bundle = fs.readFileSync(esmPath);
fs.writeFileSync(esmPath, additional + "\n" + bundle);
