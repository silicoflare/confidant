import { stringy } from "../src/utils";
import { randomBytes } from "crypto";
import chalkTemplate from "chalk-template";
import { writeFileSync } from "fs";

const envstring = `// env.ts
const env = {
  // Re-run to get a new value
  AUTH_KEY: "${stringy(randomBytes(32))}",

  // Can be literally anything!
  PHRASE: "May the Force be with you!",
}

export default env;
`;

writeFileSync("./env.ts", envstring);
console.log(chalkTemplate`{green env.ts initialized sucessfully!}`);
