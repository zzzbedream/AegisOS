import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

/** Where `npm run account:init` leaves the account and its keys. */
export const AUTHORITY_FILE = ".aegis/authority.json";
export const OWNER_FILE = ".aegis/owner.json";
export const ACCOUNT_FILE = ".aegis/account.json";

export interface SmartAccountSetup {
  readonly address: string;
  /** Absolute path, handed to the signer process — never read by the agent. */
  readonly authoritySecretFile: string;
}

/**
 * The smart account to pay from, or `undefined` for the classic `G…` mode.
 * Smart mode is on when the account exists, unless AEGIS_ACCOUNT_MODE=classic.
 */
export function loadSmartAccount(env: NodeJS.ProcessEnv = process.env): SmartAccountSetup | undefined {
  if (env["AEGIS_ACCOUNT_MODE"] === "classic") return undefined;
  if (!existsSync(ACCOUNT_FILE) || !existsSync(AUTHORITY_FILE)) return undefined;
  const { address } = JSON.parse(readFileSync(ACCOUNT_FILE, "utf8")) as { address?: unknown };
  if (typeof address !== "string" || !/^C[A-Z2-7]{55}$/.test(address)) {
    throw new Error(`${ACCOUNT_FILE} holds no valid account address.`);
  }
  return { address, authoritySecretFile: resolve(AUTHORITY_FILE) };
}
