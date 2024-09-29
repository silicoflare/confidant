#!/bin/env bun

import { input, password, select } from "@inquirer/prompts";
import { $ } from "bun";
import chalk from "chalk-template";
import { Command } from "commander";
import { decrypt_diary, encrypt_diary, initialize, recovery } from "./src/main";
import { existsSync } from "fs";
import checkForFiles, { log, panic } from "./src/utils";

const program = new Command();
const { exit } = process;
$.nothrow();

program.name("confidant").description("Creates a very secure file vault.");

program
  .command("init")
  .description("initialize a confidant vault")
  .action(async () => {
    // check if a vault already exists
    if (await $`test -e config.toml`) {
      console.log(
        chalk`{red A Confidant vault already exists in this directory.}`,
      );
      exit(1);
    }

    // select a directory
    let dirs;
    try {
      dirs = (await $`ls -d */`.text()).trim();
    } catch (e) {
      console.error(
        'No directories found in current directory, please create one and run "init" again.',
      );
      process.exit(1);
    }

    let dirlist = dirs.split("\n");
    const dirname = await select({
      message: "Select a directory to use:",
      choices: dirlist.map((x) => ({
        name: x,
        value: x,
      })),
    });
    const pass = await password({
      message: chalk`{reset {yellow Enter a password to use:}}`,
      mask: "•",
    });
    const confpass = await password({
      message: chalk`{reset {yellow Enter the password again:}}`,
      mask: "•",
    });
    if (pass !== confpass) {
      console.log(chalk`Passwords don't math.`);
      exit(1);
    }

    await initialize(pass, dirname);
    console.log(chalk`{green Initialized a new Confidant vault sucessfully!}`);
  });

program
  .command("decrypt")
  .description("decrypt the vault")
  .option("-l, --live", "decrypt in live mode")
  .action(async (args) => {
    checkForFiles();

    const pass = await password({
      message: chalk`{reset {yellow Enter the password:}}`,
      mask: "•",
    });
    await decrypt_diary(pass);
    if (args.live) {
      await input({
        message: chalk`{yellow Live mode started. Press ENTER to encrypt}`,
      });
      await encrypt_diary();
      console.log(chalk`{green Successfully encrypted!}`);
    } else {
      console.log(chalk`{green Decrypted sucessfully!}`);
    }
  });

program
  .command("encrypt")
  .description("encrypt the vault")
  .action(async () => {
    checkForFiles();

    if (!existsSync(".confidant")) {
      panic`The vault was not decrypted yet!`;
    }

    await encrypt_diary();
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
