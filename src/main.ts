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
  getRandomPassword,
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
import { input, password } from "@inquirer/prompts";

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
    Buffer.concat([
      Buffer.from(Buffer.from(JSON.stringify(D_C)).toString("base64")),
      separator,
      E_Z,
    ]),
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

export async function decrypt_vault(password: string, dirname: string) {
  try {
    // Read and split the vault file
    const combined = readFileSync(`${dirname}.vault`);
    const index = combined.indexOf(separator);
    const D_C = combined.subarray(0, index).toString("utf8");
    const E_Z = combined.subarray(index + separator.length);

    // Check if password is correct
    const password_auth_key = HmacSHA256(password, env.AUTH_KEY).toString(
      enc.Base64,
    );
    const config = JSON.parse(Buffer.from(D_C, "base64").toString());
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
  } catch (e) {
    panic`Error decrypting vault. The files could be corrupted.`;
  }
}

export async function encrypt_vault(dirname: string) {
  try {
    const D = decrypt(
      readFileSync(`.${dirname}.confidant`),
      buffer(env.AUTH_KEY),
    );
    // create zip file and encrypt it
    await $`zip -r9 confidant.zip ${dirname} > /dev/null`;
    await $`rm -rf ${dirname}`;
    const Z = readFileSync("confidant.zip");
    const E_Z = encrypt_file(Z, D);

    // read original vault file to get header data
    const vaultfile = readFileSync(`${dirname}.vault`);
    const index = vaultfile.indexOf(separator);

    // write new data to vault
    writeFileSync(
      `${dirname}.vault`,
      Buffer.concat([vaultfile.subarray(0, index), separator, E_Z]),
    );
    await $`rm confidant.zip .${dirname}.confidant`;
  } catch (e) {
    panic`Error encrypting vault. The files could be corrupted.`;
  }
}

export async function reset(dirname: string, recoverystring: string) {
  try {
    // Read and split the vault file
    const combined = readFileSync(`${dirname}.vault`);
    const index = combined.indexOf(separator);
    const D_C = combined.subarray(0, index).toString("utf8");
    const E_Z = combined.subarray(index + separator.length);

    // Check if recovery key is correct
    const recovery_auth_key = HmacSHA256(recoverystring, env.AUTH_KEY).toString(
      enc.Base64,
    );
    const config = JSON.parse(Buffer.from(D_C, "base64").toString());
    const phrase = AES.decrypt(
      config.recphrasestore,
      recovery_auth_key,
    ).toString(enc.Utf8);
    if (phrase !== env.PHRASE) {
      panic`Incorrect recovery phrase. Try again.`;
    }

    // create new credentials
    const auth_secret = decrypt(
      config.recoverystore,
      buffer(recovery_auth_key),
    );

    const genPass = getRandomPassword(14);
    const pass = await input({
      message: chalk`{reset {yellow Enter a new password:}}`,
      default: genPass,
    });
    const confpass = await input({
      message: chalk`{reset {yellow Enter the password again:}}`,
      default: genPass,
    });
    if (pass !== confpass) {
      panic`Passwords don't match. Exiting...`;
    }
    const newrecphrase = generate_recovery_phrase();

    const password_auth_key = HmacSHA256(pass, env.AUTH_KEY).toString(
      enc.Base64,
    );
    const _recovery_auth_key = HmacSHA256(newrecphrase, env.AUTH_KEY).toString(
      enc.Base64,
    );

    const _D_C = {
      ...config,
      keystore: stringy(encrypt(auth_secret, buffer(password_auth_key))),
      recoverystore: stringy(encrypt(auth_secret, buffer(_recovery_auth_key))),
      phrasestore: AES.encrypt(env.PHRASE, password_auth_key).toString(),
      recphrasestore: AES.encrypt(env.PHRASE, _recovery_auth_key).toString(),
    };

    // create dirname.vault
    writeFileSync(
      `${dirname}.vault`,
      Buffer.concat([
        Buffer.from(Buffer.from(JSON.stringify(_D_C)).toString("base64")),
        separator,
        E_Z,
      ]),
    );

    writeFileSync(`${dirname}_recovery.txt`, newrecphrase);
    console.log(`New recovery phrase:`);
    console.log(chalk`{magenta    ${newrecphrase}}`);
  } catch (e) {
    panic`Error recovering vault. The files could be corrupted.`;
  }
}
