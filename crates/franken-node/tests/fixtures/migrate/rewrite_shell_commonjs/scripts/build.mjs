import { readFileSync } from "fs";

console.log(readFileSync(new URL("../package.json", import.meta.url), "utf8").length);
