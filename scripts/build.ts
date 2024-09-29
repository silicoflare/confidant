import { $ } from "bun";
import data from "../package.json";

const { version: ver } = data;

await $`
rm -rf ./dist
bun build --compile --target=bun-linux-x64 ./confidant.ts --outfile ./dist/confidant_${ver}_linux_x64
bun build --compile --target=bun-windows-x64 ./confidant.ts --outfile ./dist/confidant_${ver}_win_x64.exe
bun build --compile --target=bun-darwin-x64 ./confidant.ts --outfile ./dist/confidant_${ver}_darwin_x64
`;
