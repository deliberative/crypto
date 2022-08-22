import { dirname } from "path";
import { createRequire } from "module";
globalThis.__dirname = dirname(import.meta.url).substring(7);
globalThis.require = createRequire(import.meta.url);
