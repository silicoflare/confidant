# Confidant

## Table of Contents

1. [Introduction](#introduction)
2. [Security](#security)
3. [Installation](#installation)
4. [Usage](#usage)
5. [Build from source](#build-from-source)
6. [Disclaimer](#disclaimer)

---

## Introduction

Confidant is a CLI tool used to create a triple-layer protected vault, written in TypeScript. It makes use of a combination of ECDH, AES256, PBKDF2 and HMAC-SHA256 to create the vault, which can be acessible only if 2 particular files, namely `dirname.vault` and `dirname.key`, are present. It also requires a password to start the decryption process. In case the password is lost, the vault can be recovered using the recovery phrase, which is a 12-word phrase that is generated during the vault creation process.

---

## Security

The vault has several layers of security to ensure that the contents are safe. The following are the security measures taken:

1. **ECDH**: The vault is encrypted using the ECDH algorithm, which is a key exchange algorithm. The key is generated using the `secp256k1` curve.
2. **AES256**: The vault is encrypted using the AES256 algorithm, which is a symmetric encryption algorithm. The key is generated using the ECDH algorithm.
3. **PBKDF2**: The password is hashed using the PBKDF2 algorithm, which is a key derivation function. This ensures that the password is not stored in plain text.
4. **HMAC-SHA256**: The keys are encrypted using the HMAC-SHA256 algorithm, which is a hash-based message authentication code. This ensures that the keys are unique and cannot be tampered with.
5. **Unique build parameters:** Every binary built by you from source has completely unique parameters in the `env.ts` file, which means ONLY that binary can be used to decrypt a vault made with the binary.

---

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

This will show a list of directories in your current directory. Select the directory where you want to create the vault. Also specify a password to encrypt the vault. The recovery phrase will be shown after the vault is created. Save it in a safe place. Assuming the selected directory is `dirname`, the following files will be created:

- `dirname.vault`: Vault file
- `dirname.key`: Key file
- `dirname_recovery.txt`: Recovery phrase
- `.gitignore`: To ignore the key files
  After this, you can push the vault files to a remote repository. The `.gitignore` file will make sure the key files are not pushed to the repository. Make sure to never store the key files in the same place as the vault files.

### Decrypt a vault

To decrypt a vault, run the following command:

```bash
confidant decrypt
```

Make sure the files `dirname.vault` and `dirname.key` are present in the current directory. Also make sure you have the password. The vault will be decrypted and the contents will be shown.

### Encrypt a vault

To encrypt a vault, run the following command:

```bash
confidant encrypt
```

Make sure the file `dirname.vault` is present in the current directory. The vault will be encrypted and the files will be updated, after which you can move them to a safe place. The key file is not required to encrypt the vault.

### Change password

To change the password of a vault, run the following command:

```bash
confidant reset
```

Make sure the files `dirname.vault` and `dirname.key` are present in the current directory. The recovery string that was generated during the vault creation process will be required. The password will be changed and the files will be updated.

---

## Build from source

To build the project from source, follow the steps below:

1. Clone the repository.
2. Run `bun install` to install the dependencies.
3. Run `bun run init` to create an `env.ts` file.
4. Modify the `env.ts` to include a unique `AUTH_KEY` and `PHRASE`.
5. Run `bun run build` to compile the project into executables for Windows, MacOS and Linux.

---

## Disclaimer

This project is built with the [Kerckhoff's Principle](https://en.wikipedia.org/wiki/Kerckhoffs%27s_principle) in mind. The security of the vault is based on the secrecy of the key files and the password. Make sure to store the key files and the password in a safe place. The recovery phrase is the only way to recover the vault in case the password is lost. Make sure to store the recovery phrase in a safe place as well. The author is not responsible for any loss of data due to misuse of the tool.
