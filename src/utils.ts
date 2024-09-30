import { AES, enc } from "crypto-js";
import { createHmac } from "crypto";
import { generatePrivate, getPublic } from "eccrypto";
import { generate } from "random-words";
import chalk from "chalk-template";
import { $ } from "bun";
import { existsSync, readdirSync } from "fs";
import { select } from "@inquirer/prompts";

export function buffer(input: string): Buffer;
export function buffer(input: string, encoding: BufferEncoding): Buffer;
export function buffer(input: string, encoding?: BufferEncoding): Buffer {
  return Buffer.from(input, encoding || "base64");
}

export function stringy(input: Buffer): string {
  return input.toString("base64");
}

export function encrypt(input: Buffer, key: Buffer) {
  const result = AES.encrypt(stringy(input), stringy(key));
  return buffer(result.toString());
}

export function decrypt(input: Buffer, key: Buffer) {
  const result = AES.decrypt(stringy(input), stringy(key));
  return buffer(result.toString(enc.Utf8));
}

export function random(start: number, end: number) {
  return Math.floor((end - start) * Math.random() + start);
}

export function ECDH() {
  const privkey = generatePrivate();
  const pubkey = getPublic(privkey);
  return [privkey, pubkey];
}

export function hmac(message: Buffer, key: Buffer): Buffer {
  return buffer(
    createHmac("sha256", stringy(key))
      .update(stringy(message))
      .digest("base64"),
  );
}

export function generate_recovery_phrase(): string {
  return (
    generate({ exactly: 12, minLength: 5, maxLength: 7 }) as string[]
  ).join(" ");
}

export function encrypt_file(input: Buffer, key: Buffer) {
  const result = AES.encrypt(input.toString("base64"), key.toString("base64"));
  return Buffer.from(result.toString(), "base64");
}

export function decrypt_file(input: Buffer, key: Buffer) {
  const result = AES.decrypt(input.toString("base64"), key.toString("base64"));
  return Buffer.from(result.toString(enc.Utf8), "base64");
}

export async function exists(dir: string) {
  try {
    await $`test -d ${dir}`;
    return true;
  } catch (e) {
    return false;
  }
}

export function log(
  str: TemplateStringsArray,
  ...placeholders: unknown[]
): void {
  console.log(chalk(str as TemplateStringsArray, ...placeholders));
}

export function panic(str: TemplateStringsArray) {
  console.log(chalk`{red ${str}}`);
  process.exit(1);
}

export default function checkForFiles() {
  const missing: string[] = [];
  ["data.con", "key.fid", "vault.ant", "config.toml"].forEach((val) => {
    if (!existsSync(val)) {
      missing.push(val);
    }
  });
  if (missing.length > 0) {
    missing.forEach((val) => {
      console.log(chalk`{red File "${val}" not found!}`);
    });
    process.exit(1);
  }
}

export const separator = Buffer.from([
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff,
]);

export function print(key: string, value: string) {
  console.log(chalk`{green ${key}:} {blue ${value}}`);
}

export class Files {
  data: string[] | null = null;

  constructor(regex: RegExp | string) {
    try {
      const data = readdirSync(".").filter((x) => x.match(regex));
      this.data = data ? data.map((x) => x.replace(regex, "$1")) : null;
    } catch (error) {
      console.error("Error executing command:", error);
      this.data = null;
    }
  }

  toString(): string {
    return `[ ${this.data ? this.data.join(", ") : "empty"} ]`;
  }

  intersection(a: Files) {
    return Array.from(new Set(this.data).intersection(new Set(a.data)));
  }

  difference(a: Files) {
    return Array.from(new Set(this.data).difference(new Set(a.data)));
  }
}

export async function getDirectoryNames() {
  const dirlist = (await $`ls -d */`.text()).trim();

  if (!dirlist) {
    panic`No directories found in current directory, please create one and run "init" again.`;
    return;
  }
  let dirs: string[];
  const vaultList = (await $`ls *.vault`.text()).trim().match(/.*\.vault/g);
  if (vaultList) {
    const vaults = vaultList.map((x) => x.replace(".vault", ""));
    dirs = Array.from(new Set(dirlist.split("\n")).difference(new Set(vaults)));
  } else {
    dirs = dirlist.split("\n");
  }

  if (dirs.length === 0) {
    panic`No usable directories found in current directory, please create one and run "init" again.`;
    return;
  } else if (dirs.length === 1) {
    return dirs[0];
  }

  const dirname = await select({
    message: "Select a directory to use:",
    choices: dirs.map((x) => ({
      name: x,
      value: x,
    })),
  });

  return dirname;
}

export async function getVaultName() {
  const vaultList = (await $`ls *.vault`.text()).trim().match(/.*\.vault/g);
  if (!vaultList) {
    panic`No vaults found in the current directory.`;
    return;
  }

  const keyList = (await $`ls *.key`.text())
    .trim()
    .match(/.*\.key/g) as string[];
  if (!keyList) {
    panic`No vaults with keys found in the current directory.`;
    return;
  }

  const vaults = Array.from(
    new Set(vaultList.map((x) => x.replace(".vault", ""))).intersection(
      new Set(keyList.map((x) => x.replace(".key", ""))),
    ),
  );

  let files: string[];
  const decryptedList = (await $`bash -c "ls .*.confidant"`.text())
    .trim()
    .match(/\.(.*)\.confidant/g);
  if (decryptedList) {
    const decs = decryptedList.map((x) => x.replace(/\.(.*)\.confidant/, "$1"));
    files = Array.from(new Set(vaults).difference(new Set(decs)));
  } else {
    files = vaultList.map((x) => x.replace(".vault", ""));
  }
  if (files.length === 1) {
    return files[0];
  }

  const vault = await select({
    message: "Select vault to decrypt:",
    choices: files.map((x) => ({
      name: x.replace(".vault", ""),
      value: x.replace(".vault", ""),
    })),
  });
  return vault;
}

export async function getDecryptedName() {
  const dec = new Files(/\.(.*)\.confidant/g);
  if (dec.data === null || dec.data.length === 0) {
    panic`No decrypted vaults found.`;
  }

  const vaults = new Files(/(.*).vault/g);
  if (vaults.data === null) {
    panic`No vaults found.`;
  }

  const decrypted = dec.intersection(vaults);

  if (decrypted.length === 1) {
    return decrypted[0];
  }

  const vault = await select({
    message: "Select vault to encrypt:",
    choices: decrypted.map((x) => ({
      name: x.replace(".vault", ""),
      value: x.replace(".vault", ""),
    })),
  });

  return vault;
}
