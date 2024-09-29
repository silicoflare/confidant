import { AES, enc } from "crypto-js";
import { createHmac } from "crypto";
import { generatePrivate, getPublic } from "eccrypto";
import { generate } from "random-words";
import chalk from "chalk-template";
import { $ } from "bun";
import { existsSync } from "fs";

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

export function log(str: TemplateStringsArray, ...placeholders: unknown[]) {
  console.log(chalk(str, placeholders));
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
