import crypto from 'crypto';
import { encrypt, decrypt } from "./blazingOpossum.js";

const myKey = crypto.randomBytes(32);
const myIv = crypto.randomBytes(16);
const msg = "Secret message post-quantum!";

console.log("Started testing encrypt + decrypt cycles (1.000.000 Million) how much time take.");
const start = process.hrtime.bigint();

for (var i = 0; i < 1000000; i++) {
    const encrypted = encrypt(myKey, myIv, msg);
    // console.log("Encrypted (Hex):", encrypted.toString('hex'));

    const decrypted = decrypt(myKey, myIv, encrypted);
    // console.log("Decrypted:", decrypted.toString());
}

const end = process.hrtime.bigint();
const durationMs = Number(end - start) / 1_000_000;
console.log(`Finished cycles! Duration: ${durationMs} ms.`);
console.log("Consider: 10.000.000 million cycles took ~4950ms in C# with Ryzen 5 3600 + 32 GB RAM DDR4 3600 MHz. Here it took ~10905ms with the same hardware...");