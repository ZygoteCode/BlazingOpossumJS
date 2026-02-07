const { BlazingOpossum } = require('./build/Release/blazing_opossum');
const crypto = require('crypto');

const key = crypto.randomBytes(32);
const iv = crypto.randomBytes(16);
const plaintext = Buffer.from("Message to be encrypted with BlazingOpossum");

try {
    const cipher = new BlazingOpossum(key);

    console.time("EncryptionTime");
    const encrypted = cipher.encrypt(iv, plaintext);
    console.timeEnd("EncryptionTime");

    console.log("Encrypted (Hex):", Buffer.from(encrypted).toString('hex'));

    console.time("DecryptionTime");
    const decrypted = cipher.decrypt(iv, encrypted);
    console.timeEnd("DecryptionTime");

    console.log("Decrypted Text:", Buffer.from(decrypted).toString());

    encrypted[0] ^= 0xFF;
    console.log("\nTest manipulation:");
    cipher.decrypt(iv, encrypted);
} catch (err) {
    console.log("Error happened: " + err);
}

console.log("\nStarting stress test (1M cycles)...");
const cipherBench = new BlazingOpossum(key);
console.time("Benchmark1M");
for(let i=0; i< 1000000; i++) {
    const encrypted = cipherBench.encrypt(iv, plaintext);
    const decrypted = cipherBench.decrypt(iv, encrypted);
}
console.timeEnd("Benchmark1M");