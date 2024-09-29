import { parse, stringify } from "@iarna/toml";
import { $ } from "bun";
import { pbkdf2Sync as pbkdf2, randomBytes } from "crypto";
import { derive, getPublic } from "eccrypto";
import { readFileSync, writeFileSync } from "fs";
import {
  buffer,
  decrypt,
  decrypt_file,
  ECDH,
  encrypt,
  encrypt_file,
  generate_recovery_phrase,
  hmac,
  log,
  panic,
  print,
  random,
  separator,
  stringy,
} from "./utils";
import env from "../env";
import { AES, enc, HmacSHA256 } from "crypto-js";
import chalk from "chalk-template";
import type { ConData, Config, FidData } from "../types";
import { password } from "@inquirer/prompts";

console.info = function () {};
const { exit } = process;

export async function initialize(password: string, dirname: string) {
  // compressing and encrypting vault
  const [K_A, P_A] = ECDH();
  const [K_B, P_B] = ECDH();
  const S_AB = await derive(K_A, P_B);
  const salt = randomBytes(32);
  const code = random(10000, 100000);
  const D = pbkdf2(S_AB, salt, code, 64, "sha256");
  await $`zip -r9 confidant.zip ${dirname} > /dev/null`;
  await $`rm -rf ${dirname}`;
  const Z = readFileSync("confidant.zip");
  const E_Z = encrypt_file(Z, D);

  // creating dirname.key
  const keyfile = {
    salt: stringy(salt),
    code: code,
    privateKey: stringy(K_A),
  };
  const auth_secret = randomBytes(32);
  const confsalt = randomBytes(64);
  const K = hmac(auth_secret, confsalt);
  const E_K = encrypt_file(Buffer.from(JSON.stringify(keyfile), "utf8"), K);
  writeFileSync(`${dirname}.key`, E_K);

  // creating config data
  const recovery_phrase = generate_recovery_phrase();
  writeFileSync(`${dirname}_recovery.txt`, recovery_phrase + "\n");
  const recovery_auth_key = HmacSHA256(recovery_phrase, env.AUTH_KEY).toString(
    enc.Base64,
  );
  const password_auth_key = HmacSHA256(password, env.AUTH_KEY).toString(
    enc.Base64,
  );
  const D_C = {
    dir: dirname,
    confsalt: stringy(confsalt),
    privateKey: stringy(K_B),
    keystore: stringy(encrypt(auth_secret, buffer(password_auth_key))),
    recoverystore: stringy(encrypt(auth_secret, buffer(recovery_auth_key))),
    phrasestore: AES.encrypt(env.PHRASE, password_auth_key).toString(),
    recphrasestore: AES.encrypt(env.PHRASE, recovery_auth_key).toString(),
  };

  // create dirname.vault
  writeFileSync(
    `${dirname}.vault`,
    Buffer.concat([Buffer.from(JSON.stringify(D_C)), separator, E_Z]),
  );

  console.log(`Recovery phrase:`);
  console.log(chalk`{magenta    ${recovery_phrase}}`);
  await $`rm confidant.zip`;

  // create .gitignore
  const gitignore = `# .gitignore

*.con
*.fid
*_recovery.txt
confidant.zip
*.confidant
`;
  writeFileSync(`.gitignore`, gitignore);
}

export async function decrypt_diary(password: string, dirname: string) {
  // Read and split the vault file
  const combined = readFileSync(`${dirname}.vault`);
  const index = combined.indexOf(separator);
  const D_C = combined.subarray(0, index).toString("utf8");
  const E_Z = combined.subarray(index + separator.length);

  // Check if password is correct
  const password_auth_key = HmacSHA256(password, env.AUTH_KEY).toString(
    enc.Base64,
  );
  const config = JSON.parse(D_C);
  const phrase = AES.decrypt(config.phrasestore, password_auth_key).toString(
    enc.Utf8,
  );
  if (phrase !== env.PHRASE) {
    panic`Incorrect password. Try again or reset it.`;
  }

  const auth_secret = decrypt(config.keystore, buffer(password_auth_key));
  const K = hmac(auth_secret, config.confsalt);
  const E_K = readFileSync(`${dirname}.key`);
  const keyfile = JSON.parse(decrypt_file(E_K, K).toString("utf8"));

  const K_A = buffer(keyfile.privateKey);
  const K_B = buffer(config.privateKey);
  const P_B = getPublic(K_B);
  const S_AB = await derive(K_A, P_B);
  const D = pbkdf2(S_AB, buffer(keyfile.salt), keyfile.code, 64, "sha256");

  const Z = decrypt_file(E_Z, D);
  writeFileSync(`confidant.zip`, Z);
  writeFileSync(`.${dirname}.confidant`, encrypt(D, buffer(env.AUTH_KEY)));
  await $`unzip confidant.zip > /dev/null && rm confidant.zip`;
}

export async function encrypt_diary() {
  const { dirname, key }: { dirname: string; key: string } = JSON.parse(
    decrypt(readFileSync(".confidant"), buffer(env.AUTH_KEY)).toString("utf8"),
  );
  const D = buffer(key);
  await $`zip -r9 confidant.zip ${dirname} > /dev/null`;
  await $`rm -rf ${dirname}`;
  const Z = readFileSync("confidant.zip");
  const E_Z = encrypt_file(Z, D);
  writeFileSync(`vault.ant`, E_Z);
  await $`rm confidant.zip .confidant`;
}

export async function recovery(recoverystring: string) {
  // Check if recovery phrase is correct
  let config = Object(parse(readFileSync("config.toml").toString("utf8")));
  let recovery_auth_key = HmacSHA256(recoverystring, env.AUTH_KEY).toString(
    enc.Base64,
  );
  const dec = AES.decrypt(
    config.config.recphrasestore,
    recovery_auth_key,
  ).toString(enc.Utf8);
  if (dec !== env.PHRASE) {
    panic`Wrong recovery string. Please try again.`;
  }

  // Generate a fresh config file
  const auth_secret = decrypt(
    buffer(config.config.recoverystore),
    buffer(recovery_auth_key),
  );
  const newpass = await password({
    message: chalk`{reset {yellow Enter a new password:}}`,
    mask: "•",
  });
  const recstring = generate_recovery_phrase();
  recovery_auth_key = HmacSHA256(recstring, env.AUTH_KEY).toString(enc.Base64);
  const password_auth_key = HmacSHA256(newpass, env.AUTH_KEY).toString(
    enc.Base64,
  );

  config.config = {
    ...config.config,
    keystore: stringy(encrypt(auth_secret, buffer(password_auth_key))),
    recoverystore: stringy(encrypt(auth_secret, buffer(recovery_auth_key))),
    phrasestore: AES.encrypt(env.PHRASE, password_auth_key).toString(),
    recphrasestore: AES.encrypt(env.PHRASE, recovery_auth_key).toString(),
  };
  writeFileSync("config.toml", buffer(stringify(config), "utf8"));

  writeFileSync("recovery.txt", recstring + "\n");
  console.log(`New recovery phrase:`);
  log`{magenta    ${recstring}}`;
}
