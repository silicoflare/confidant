import { $ } from "bun";
import { stringy } from "../src/utils";
import { randomBytes } from "crypto";
import chalkTemplate from "chalk-template";

const envstring = `// env.ts
const env = {
  // Re-run to get a new value
  AUTH_KEY: "${stringy(randomBytes(32))}",

  // Can be literally anything!
  PHRASE: "May the Force be with you!",
}

export default env;
`;

await $`echo ${envstring} > env.ts`;
console.log(chalkTemplate`{green env.ts initialized sucessfully!}`);
