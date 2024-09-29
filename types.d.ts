export interface Config {
  config: {
    con: string;
    fid: string;
    ant: string;
    dir: string;
    keystore: string;
    recoverystore: string;
    phrasestore: string;
    recphrasestore: string;
  };
}

export interface ConData {
  privateKey: string;
  fidkey: string;
  consalt: string;
}

export interface FidData {
  privateKey: string;
  salt: string;
  code: number;
}
