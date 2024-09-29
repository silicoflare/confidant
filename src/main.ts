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
  random,
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
  // compressing and encrypting diary
  const [K_C, P_C] = ECDH();
  const [K_F, P_F] = ECDH();
  const S_CF = await derive(K_C, P_F);
  const fidsalt = randomBytes(32);
  const fidcode = random(10000, 100000);
  const D = pbkdf2(S_CF, fidsalt, fidcode, 64, "sha256");
  await $`zip -r9 confidant.zip ${dirname} > /dev/null`;
  await $`rm -rf ${dirname}`;
  const Z = readFileSync("confidant.zip");
  const E_Z = encrypt_file(Z, D);
  writeFileSync(`vault.ant`, E_Z);

  // creating key.fid
  const fidData = {
    privateKey: stringy(K_F),
    salt: stringy(fidsalt),
    code: fidcode,
  };
  const fidkey = randomBytes(32);
  const consalt = randomBytes(32);
  const D_C = hmac(consalt, fidkey);
  const E_F = encrypt_file(buffer(stringify(fidData), "utf8"), D_C);
  writeFileSync(`key.fid`, E_F);

  // create data.con
  const auth_secret = randomBytes(32);
  const conData = {
    privateKey: stringy(K_C),
    fidkey: stringy(fidkey),
    consalt: stringy(consalt),
  };
  const D_U = hmac(auth_secret, buffer(env.AUTH_KEY));
  const E_C = encrypt_file(buffer(stringify(conData), "utf8"), D_U);
  writeFileSync("data.con", E_C);

  const recovery_phrase = generate_recovery_phrase();
  writeFileSync("recovery.txt", recovery_phrase + "\n");
  const recovery_auth_key = HmacSHA256(recovery_phrase, env.AUTH_KEY).toString(
    enc.Base64,
  );
  const password_auth_key = HmacSHA256(password, env.AUTH_KEY).toString(
    enc.Base64,
  );

  // create config.toml
  const configData = {
    config: {
      con: "data.con",
      fid: "key.fid",
      ant: "vault.ant",
      dir: dirname,
      keystore: stringy(encrypt(auth_secret, buffer(password_auth_key))),
      recoverystore: stringy(encrypt(auth_secret, buffer(recovery_auth_key))),
      phrasestore: AES.encrypt(env.PHRASE, password_auth_key).toString(),
      recphrasestore: AES.encrypt(env.PHRASE, recovery_auth_key).toString(),
    },
  };
  writeFileSync("config.toml", buffer(stringify(configData), "utf8"));
  console.log(`Recovery phrase:`);
  console.log(chalk`{magenta    ${recovery_phrase}}`);
  await $`rm confidant.zip`;

  const gitignore = `# .gitignore

data.con
key.fid
recovery.txt
confidant.zip
.confidant
${dirname}
.env
`;
  writeFileSync(".gitignore", gitignore);
}

export async function decrypt_diary(password: string) {
  // Check if password is correct
  const config = Object(
    parse(readFileSync("config.toml").toString("utf8")),
  ) as Config;
  const password_auth_key = HmacSHA256(password, env.AUTH_KEY).toString(
    enc.Base64,
  );
  const dec = AES.decrypt(
    config.config.phrasestore,
    password_auth_key,
  ).toString(enc.Utf8);
  if (dec !== env.PHRASE) {
    panic`Wrong password. Try again or reset it.`;
  }

  // Decrypt data.con
  const auth_secret = decrypt(
    buffer(config.config.keystore),
    buffer(password_auth_key),
  );
  const D_U = hmac(auth_secret, buffer(env.AUTH_KEY));
  const conData = Object(
    parse(decrypt_file(readFileSync(config.config.con), D_U).toString("utf8")),
  ) as ConData;

  // Decrypt key.fid
  const { consalt, fidkey, privateKey: conK } = conData;
  const D_C = hmac(buffer(consalt), buffer(fidkey));
  const fidData = Object(
    parse(decrypt_file(readFileSync(config.config.fid), D_C).toString("utf8")),
  ) as FidData;
  const { privateKey: fidK, salt, code } = fidData;

  // Decrypt diary.ant
  const S_CF = await derive(buffer(conK), getPublic(buffer(fidK)));
  const D = pbkdf2(S_CF, buffer(salt), code, 64, "sha256");
  writeFileSync(
    ".confidant",
    encrypt(
      Buffer.from(
        JSON.stringify({
          dirname: config.config.dir,
          key: stringy(D),
        }),
        "utf8",
      ),
      buffer(env.AUTH_KEY),
    ),
  );
  writeFileSync(
    "confidant.zip",
    decrypt_file(readFileSync(config.config.ant), D),
  );
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
