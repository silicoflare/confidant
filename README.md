# Confidant

## Table of Contents
1. [Introduction](#introduction)
2. [Installation](#installation)
  a. [Linux](#linux)
  b. [Windows](#windows)
  c. [MacOS](#macos)
3. [Usage](#usage)
4. [Build from source](#build-from-source)
---

## Introduction
Confidant is a CLI tool used to create a triple-layer protected vault, written in TypeScript. It makes use of a combination of ECDH, AES256 and HMAC-SHA256 to create the vault, which can be acessible only if 3 particular files, namely `data.con`, `key.fid` and `vault.ant` (and a `config.toml`), are present. It also requires a password to start the decryption process. In case the password is lost, the vault can be recovered using the recovery phrase, which is a 12-word phrase that is generated during the vault creation process.

## Installation
### Linux
1. Download the latest release from the releases page.
2. Give it executable permissions by running `chmod +x confidant`.
3. Move it to a directory in your PATH, like `/usr/local/bin`.
4. Run `confidant --help` to verify the installation.

### Windows
1. Download the latest release from the releases page.
2. Move it to a directory in your PATH.
3. Run `confidant --help` to verify the installation.

### MacOS
1. Download the latest release from the releases page.
2. Give it executable permissions by running `chmod +x confidant`.
3. Move it to a directory in your PATH, like `/usr/local/bin`.
4. Run `confidant --help` to verify the installation.

---

## Usage
### Create a new vault
To create a new vault, run the following command:
```bash
confidant init
```
This will show a list of directories in your current directory. Select the directory where you want to create the vault. Also specify a password to encrypt the vault. The recovery phrase will be shown after the vault is created. Save it in a safe place. The following files will be created:
- `data.con`: Primary key
- `key.fid`: Secondary key
- `vault.ant`: Encrypted vault
- `config.toml`: Configuration file
- `.gitignore`: To ignore the vault files
After this, you can push the vault files to a remote repository. The `.gitignore` file will make sure the key files are not pushed to the repository. Make sure to never store the key files in the same place as the vault files.

### Decrypt a vault
To decrypt a vault, run the following command:
```bash
confidant decrypt
```
Make sure all the files `data.con`, `key.fid` and `vault.ant` are present in the current directory. Also make sure you have the password and the recovery phrase. The vault will be decrypted and the contents will be shown.

### Encrypt a vault
To encrypt a vault, run the following command:
```bash
confidant encrypt
```
Make sure the files `data.con`, `key.fid` and `vault.ant` are present in the current directory. The vault will be encrypted and the files will be updated, after which you can move them to a safe place.
