#!/bin/env bun

import { input, password } from "@inquirer/prompts";
import { $ } from "bun";
import chalk from "chalk-template";
import { Command } from "commander";
import { decrypt_vault, encrypt_vault, initialize, recovery } from "./src/main";
import { existsSync, readdirSync } from "fs";
import checkForFiles, {
  Files,
  getDecryptedName,
  getDirectoryNames,
  getRandomPassword,
  getVaultName,
  log,
  panic,
} from "./src/utils";
import { randomBytes } from "crypto";

const program = new Command();
const { exit } = process;
$.nothrow();

program.name("confidant").description("Creates a very secure file vault.");

program
  .command("init")
  .description("initialize a confidant vault")
  .argument("[directory]", "Directory to use to create a vault")
  .action(async (dirname) => {
    if (!dirname) {
      dirname = (await getDirectoryNames()) as string;
    }
    const selectedDir = readdirSync(".").filter((x) => x.match(dirname))[0];

    if (!selectedDir) {
      console.log(
        chalk`{red Directory "${dirname}" not found in current location.}`,
      );
      exit(1);
    }

    log`{blue Using "{green ${dirname}}" to create a vault...}`;
    const genPass = getRandomPassword(14);
    const pass = await input({
      message: chalk`{reset {yellow Enter a password to use:}}`,
      default: genPass,
    });
    const confpass = await input({
      message: chalk`{reset {yellow Enter the password again:}}`,
      default: genPass,
    });
    if (pass !== confpass) {
      panic`Passwords don't match. Exiting...`;
    }

    await initialize(pass, dirname);
    console.log(chalk`{green Initialized a new Confidant vault sucessfully!}`);
  });

program
  .command("decrypt")
  .description("decrypt the vault")
  .argument("[vault]", "Name of the vault to decrypt")
  .option("-l, --live", "decrypt in live mode")
  .action(async (args, opts) => {
    if (!args) {
      args = await getVaultName();
    } else {
      const vaults = new Files(/(.*).vault/g).intersection(
        new Files(/(.*).key/g),
      ).data as string[];
      if (!vaults.includes(args)) {
        console.log(
          chalk`{red Vault "${args}" not found in current directory.}`,
        );
        exit(1);
      }
    }

    log`{blue Decrypting "{green ${args}}"...}`;
    const pass = await password({
      message: chalk`{reset {yellow Enter the password:}}`,
      mask: "•",
    });
    await decrypt_vault(pass, args);
    if (opts.live) {
      await input({
        message: chalk`{yellow Live mode started. Press ENTER to encrypt:}`,
      });
      await encrypt_vault(args);
      console.log(chalk`{green Encrypted successfully!}`);
    } else {
      console.log(chalk`{green Decrypted sucessfully!}`);
    }
  });

program
  .command("encrypt")
  .description("encrypt the vault")
  .argument("[vault]", "Name of the vault to decrypt")
  .action(async (vault) => {
    if (!vault) {
      vault = await getDecryptedName();
    } else {
      const vaults = new Files(/(.*).vault/g).intersection(
        new Files(/\.(.*)\.confidant/g),
      ).data as string[];
      if (!vaults.includes(vault)) {
        console.log(
          chalk`{red Vault "${vault}" not found in current directory.}`,
        );
        exit(1);
      }
    }

    await encrypt_vault(vault);
    console.log(chalk`{green Successfully encrypted!}`);
  });

program
  .command("recover")
  .description("recover vault when password is forgotten")
  .action(async () => {
    checkForFiles();

    const recphrase = await input({
      message: chalk`{reset {yellow Enter the recovery phrase:}}`,
    });
    recovery(recphrase);
  });

await program.parseAsync();
