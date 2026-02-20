import { randomBytes } from "node:crypto";
import { getPublicKeyAsync } from "@noble/ed25519";

const sk = randomBytes(32);
const pk = await getPublicKeyAsync(sk);

const b64 = (u) => Buffer.from(u).toString("base64");

console.log("ISSUER_ED25519_PRIVATE_KEY_B64=" + b64(sk));
console.log("ISSUER_ED25519_PUBLIC_KEY_B64=" + b64(pk));
