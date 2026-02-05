"use strict";
import crypto from 'crypto';

class BlazingOpossum {
    static ROUNDS = 20;
    static PRIME_MUL = 0x9E3779B9 >>> 0;
    static PRIME_ADD = 0xBB67AE85 >>> 0;

    constructor(key) {
        if (key.length !== 32) throw new Error("Key must be 32 bytes.");
        this.roundKeys = this._expandKey(Buffer.from(key));
    }

    _rotl(v, n) {
        return ((v << n) | (v >>> (32 - n))) >>> 0;
    }

    _shuffle(vec, control) {
        const res = new Uint32Array(8);
        const idx = [
            (control & 0x03),
            (control >> 2) & 0x03,
            (control >> 4) & 0x03,
            (control >> 6) & 0x03
        ];
        for (let i = 0; i < 4; i++) res[i] = vec[idx[i]];
        for (let i = 0; i < 4; i++) res[i + 4] = vec[idx[i] + 4];
        return res;
    }

    _expandKey(key) {
        const numRoundKeys = BlazingOpossum.ROUNDS + 2;
        const roundKeys = [];
        
        let kVec = new Uint32Array(8);
        for (let i = 0; i < 8; i++) kVec[i] = key.readUInt32LE(i * 4);

        let state = new Uint32Array([
            0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
            0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
        ]);

        for (let i = 0; i < numRoundKeys; i++) {
            let nextState = new Uint32Array(8);
            for (let j = 0; j < 8; j++) {
                let mixed = (Math.imul(state[j], BlazingOpossum.PRIME_MUL) + kVec[j]) >>> 0;
                nextState[j] = mixed;
            }

            let permuted = this._shuffle(nextState, 0xB1);

            for (let j = 0; j < 8; j++) {
                state[j] = this._rotl(state[j] ^ permuted[j], 7);
                kVec[j] = (kVec[j] + BlazingOpossum.PRIME_ADD) >>> 0;
            }
            roundKeys.push(new Uint32Array(state));
        }
        return roundKeys;
    }

    _generateKeystreamBlock(ivLow, ivHigh, counterStart) {
        const c1 = ivLow + counterStart;
        const c2 = ivLow + counterStart + 1n;

        let state = new Uint32Array([
            Number(ivHigh >> 32n) >>> 0, Number(ivHigh & 0xFFFFFFFFn) >>> 0,
            Number(c1 >> 32n) >>> 0, Number(c1 & 0xFFFFFFFFn) >>> 0,
            Number(ivHigh >> 32n) >>> 0, Number(ivHigh & 0xFFFFFFFFn) >>> 0,
            Number(c2 >> 32n) >>> 0, Number(c2 & 0xFFFFFFFFn) >>> 0
        ]);

        for (let r = 0; r < BlazingOpossum.ROUNDS; r++) {
            const rk = this.roundKeys[r];
            for (let i = 0; i < 8; i++) {
                state[i] = (Math.imul(state[i], BlazingOpossum.PRIME_MUL) + rk[i]) >>> 0;
            }

            state = this._shuffle(state, 0x4B);

            for (let i = 0; i < 8; i++) {
                let rot1 = this._rotl(state[i], 13);
                state[i] = (state[i] ^ rot1) >>> 0;
                state[i] = (state[i] + BlazingOpossum.PRIME_ADD) >>> 0;
            }
        }

        const whitening = this.roundKeys[BlazingOpossum.ROUNDS];
        const out = Buffer.alloc(32);
        for (let i = 0; i < 8; i++) {
            out.writeUInt32LE((state[i] ^ whitening[i]) >>> 0, i * 4);
        }
        return out;
    }

    _computeTag(data, iv) {
        let acc = new Uint32Array(8);
        for (let i = 0; i < 4; i++) {
            acc[i] = iv.readUInt32LE(i * 4);
            acc[i + 4] = acc[i];
        }

        let offset = 0;
        while (offset < data.length) {
            let block = new Uint32Array(8);
            for (let j = 0; j < 8; j++) {
                const readPos = offset + (j * 4);
                if (readPos + 4 <= data.length) {
                    block[j] = data.readUInt32LE(readPos);
                } else if (readPos < data.length) {
                    let remaining = data.length - readPos;
                    let lastVal = 0;
                    for (let b = 0; b < remaining; b++) {
                        lastVal |= (data[readPos + b] << (b * 8));
                    }
                    block[j] = lastVal >>> 0;
                }
            }

            for (let i = 0; i < 8; i++) {
                acc[i] ^= block[i];
                acc[i] = (Math.imul(acc[i], BlazingOpossum.PRIME_MUL) + BlazingOpossum.PRIME_ADD) >>> 0;
                acc[i] = this._rotl(acc[i], 11);
            }
            offset += 32;
        }

        for (let r = 0; r < 4; r++) {
            const rk = this.roundKeys[r];
            for (let i = 0; i < 8; i++) {
                acc[i] = (acc[i] + rk[i]) >>> 0;
                acc[i] = Math.imul(acc[i], BlazingOpossum.PRIME_MUL) >>> 0;
            }
            acc = this._shuffle(acc, 0xB1);
        }

        const tag = Buffer.alloc(16);
        for (let i = 0; i < 4; i++) {
            tag.writeUInt32LE((acc[i] ^ acc[i + 4]) >>> 0, i * 4);
        }
        return tag;
    }

    encrypt(iv, plaintext) {
        const ivBuf = Buffer.from(iv);
        const ptBuf = Buffer.from(plaintext);
        const ivLow = ivBuf.readBigUInt64LE(0);
        const ivHigh = ivBuf.readBigUInt64LE(8);

        let ciphertext = Buffer.alloc(ptBuf.length);
        let counter = 0n;
        let offset = 0;

        while (offset < ptBuf.length) {
            const keystream = this._generateKeystreamBlock(ivLow, ivHigh, counter);
            const bytesToXor = Math.min(32, ptBuf.length - offset);
            for (let i = 0; i < bytesToXor; i++) {
                ciphertext[offset + i] = ptBuf[offset + i] ^ keystream[i];
            }
            offset += 32;
            counter += 2n;
        }

        const tag = this._computeTag(ciphertext, ivBuf);
        return Buffer.concat([ciphertext, tag]);
    }

    decrypt(iv, encryptedData) {
        if (encryptedData.length < 16) throw new Error("Data too short.");
        
        const cipherLen = encryptedData.length - 16;
        const ciphertext = encryptedData.slice(0, cipherLen);
        const receivedTag = encryptedData.slice(cipherLen);
        const ivBuf = Buffer.from(iv);

        const computedTag = this._computeTag(ciphertext, ivBuf);
        if (!crypto.timingSafeEqual(computedTag, receivedTag)) {
            throw new Error("Integrity Check Failed: Message has been tampered with.");
        }

        const ivLow = ivBuf.readBigUInt64LE(0);
        const ivHigh = ivBuf.readBigUInt64LE(8);
        let plaintext = Buffer.alloc(cipherLen);
        let counter = 0n;
        let offset = 0;

        while (offset < cipherLen) {
            const keystream = this._generateKeystreamBlock(ivLow, ivHigh, counter);
            const bytesToXor = Math.min(32, cipherLen - offset);
            for (let i = 0; i < bytesToXor; i++) {
                plaintext[offset + i] = ciphertext[offset + i] ^ keystream[i];
            }
            offset += 32;
            counter += 2n;
        }
        return plaintext;
    }
}

function encrypt(key, iv, toEncrypt) {
    const engine = new BlazingOpossum(key);
    return engine.encrypt(iv, toEncrypt);
}

function decrypt(key, iv, toDecrypt) {
    const engine = new BlazingOpossum(key);
    return engine.decrypt(iv, toDecrypt);
}

export { encrypt, decrypt };