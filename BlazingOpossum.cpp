#include <napi.h>
#include <immintrin.h> 
#include <vector>
#include <stdexcept>
#include <cstring>

#if defined(_MSC_VER)
#define ALIGN32 __declspec(align(32))
#else
#define ALIGN32 __attribute__((aligned(32)))
#endif

class BlazingOpossum : public Napi::ObjectWrap<BlazingOpossum> {
public:
    static Napi::Object Init(Napi::Env env, Napi::Object exports);
    BlazingOpossum(const Napi::CallbackInfo& info);

private:
    static const int BlockSize = 16;       //
    static const int KeySize = 32;         //
    static const int IvSize = 16;          //
    static const int TagSize = 16;         //
    static const int Rounds = 20;          //

    __m256i _roundKeys[Rounds + 2];
    const uint32_t PRIME_MUL_VAL = 0x9E3779B9; 
    const uint32_t PRIME_ADD_VAL = 0xBB67AE85; 

    void ExpandKeySIMD(const uint8_t* key);
    void ProcessCtrParallel(const uint8_t* ivPtr, const uint8_t* inPtr, uint8_t* outPtr, size_t length);
    __m256i GenerateKeystreamBlock(uint64_t ivLow, uint64_t ivHigh, uint64_t counterStart);
    void ComputeTag(const uint8_t* data, size_t length, const uint8_t* iv, uint8_t* tagOut);

    Napi::Value Encrypt(const Napi::CallbackInfo& info);
    Napi::Value Decrypt(const Napi::CallbackInfo& info);

    inline __m256i RotateLeft(const __m256i x, int n) {
        return _mm256_or_si256(_mm256_slli_epi32(x, n), _mm256_srli_epi32(x, 32 - n));
    }
};

Napi::Object BlazingOpossum::Init(Napi::Env env, Napi::Object exports) {
    Napi::Function func = DefineClass(env, "BlazingOpossum", {
        InstanceMethod("encrypt", &BlazingOpossum::Encrypt),
        InstanceMethod("decrypt", &BlazingOpossum::Decrypt)
    });
    exports.Set("BlazingOpossum", func);
    return exports;
}

BlazingOpossum::BlazingOpossum(const Napi::CallbackInfo& info) : Napi::ObjectWrap<BlazingOpossum>(info) {
    Napi::Env env = info.Env();
    
    if (info.Length() < 1 || !info[0].IsTypedArray()) {
        Napi::TypeError::New(env, "Key must be a Uint8Array").ThrowAsJavaScriptException();
        return;
    }

    Napi::Uint8Array keyArr = info[0].As<Napi::Uint8Array>();
    if (keyArr.ByteLength() != KeySize) {
        Napi::Error::New(env, "Key must be exactly 32 bytes").ThrowAsJavaScriptException();
        return;
    }
    ExpandKeySIMD(keyArr.Data());
}

void BlazingOpossum::ExpandKeySIMD(const uint8_t* key) {
    __m256i kVec = _mm256_loadu_si256((const __m256i*)key);
    
    __m256i state = _mm256_setr_epi32(0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
                                     0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19);
    __m256i pMul = _mm256_set1_epi32(PRIME_MUL_VAL);
    __m256i pAdd = _mm256_set1_epi32(PRIME_ADD_VAL);

    for (int i = 0; i < Rounds + 2; i++) {
        __m256i mixed = _mm256_add_epi32(_mm256_mullo_epi32(state, pMul), kVec);
        
        __m256i permuted = _mm256_shuffle_epi32(mixed, 0xB1);
        
        state = _mm256_xor_si256(state, permuted);
        state = RotateLeft(state, 7);
        
        _roundKeys[i] = state;
        kVec = _mm256_add_epi32(kVec, pAdd);
    }
}

__m256i BlazingOpossum::GenerateKeystreamBlock(uint64_t ivLow, uint64_t ivHigh, uint64_t counterStart) {
    uint64_t c1 = ivLow + counterStart;
    uint64_t c2 = ivLow + counterStart + 1;

    __m256i state = _mm256_setr_epi32(
        (uint32_t)(ivHigh >> 32), (uint32_t)ivHigh, (uint32_t)(c1 >> 32), (uint32_t)c1,
        (uint32_t)(ivHigh >> 32), (uint32_t)ivHigh, (uint32_t)(c2 >> 32), (uint32_t)c2
    );

    __m256i pMul = _mm256_set1_epi32(PRIME_MUL_VAL);
    __m256i pAdd = _mm256_set1_epi32(PRIME_ADD_VAL);

    for (int r = 0; r < Rounds; r++) {
        state = _mm256_add_epi32(_mm256_mullo_epi32(state, pMul), _roundKeys[r]);
        state = _mm256_shuffle_epi32(state, 0x4B);
        state = _mm256_xor_si256(state, RotateLeft(state, 13));
        state = _mm256_add_epi32(state, pAdd);
    }

    return _mm256_xor_si256(state, _roundKeys[Rounds]);
}

void BlazingOpossum::ProcessCtrParallel(const uint8_t* ivPtr, const uint8_t* inPtr, uint8_t* outPtr, size_t length) {
    uint64_t ivLow = *(uint64_t*)ivPtr;
    uint64_t ivHigh = *(uint64_t*)(ivPtr + 8);
    
    size_t chunks = length / 128;
    size_t remainder = length;
    uint64_t counter = 0;

    for (size_t i = 0; i < chunks; i++) {
        __m256i k0 = GenerateKeystreamBlock(ivLow, ivHigh, counter + 0);
        __m256i k1 = GenerateKeystreamBlock(ivLow, ivHigh, counter + 2);
        __m256i k2 = GenerateKeystreamBlock(ivLow, ivHigh, counter + 4);
        __m256i k3 = GenerateKeystreamBlock(ivLow, ivHigh, counter + 6);

        _mm256_storeu_si256((__m256i*)outPtr, _mm256_xor_si256(_mm256_loadu_si256((const __m256i*)inPtr), k0));
        _mm256_storeu_si256((__m256i*)(outPtr + 32), _mm256_xor_si256(_mm256_loadu_si256((const __m256i*)(inPtr + 32)), k1));
        _mm256_storeu_si256((__m256i*)(outPtr + 64), _mm256_xor_si256(_mm256_loadu_si256((const __m256i*)(inPtr + 64)), k2));
        _mm256_storeu_si256((__m256i*)(outPtr + 96), _mm256_xor_si256(_mm256_loadu_si256((const __m256i*)(inPtr + 96)), k3));

        inPtr += 128; outPtr += 128; counter += 8; remainder -= 128;
    }

    if (remainder > 0) {
        while (remainder > 0) {
            ALIGN32 __m256i kVec = GenerateKeystreamBlock(ivLow, ivHigh, counter);
            uint8_t* kBytes = (uint8_t*)&kVec;
            size_t toProcess = (remainder < 16) ? remainder : 16;
            for (size_t i = 0; i < toProcess; i++) *outPtr++ = *inPtr++ ^ kBytes[i];
            remainder -= toProcess;
            if (remainder > 0) {
                size_t secondPart = (remainder < 16) ? remainder : 16;
                for (size_t i = 0; i < secondPart; i++) *outPtr++ = *inPtr++ ^ kBytes[16 + i];
                remainder -= secondPart;
            }
            counter += 2;
        }
    }
}

void BlazingOpossum::ComputeTag(const uint8_t* data, size_t length, const uint8_t* iv, uint8_t* tagOut) {
    __m256i acc = _mm256_setr_epi32(*(uint32_t*)iv, *(uint32_t*)(iv+4), *(uint32_t*)(iv+8), *(uint32_t*)(iv+12), 0,0,0,0);
    __m256i pMul = _mm256_set1_epi32(PRIME_MUL_VAL);
    __m256i pAdd = _mm256_set1_epi32(PRIME_ADD_VAL);

    size_t chunks = length / 32;
    for (size_t i = 0; i < chunks; i++) {
        acc = _mm256_xor_si256(acc, _mm256_loadu_si256((const __m256i*)(data + i * 32)));
        acc = _mm256_add_epi32(_mm256_mullo_epi32(acc, pMul), pAdd);
        acc = RotateLeft(acc, 11);
    }

    size_t rem = length % 32;
    if (rem > 0) {
        ALIGN32 uint8_t lastBlock[32] = {0};
        memcpy(lastBlock, data + (chunks * 32), rem);
        acc = _mm256_xor_si256(acc, _mm256_loadu_si256((const __m256i*)lastBlock));
    }

    for (int r = 0; r < 4; r++) {
        acc = _mm256_add_epi32(acc, _roundKeys[r]);
        acc = _mm256_mullo_epi32(acc, pMul);
        acc = _mm256_xor_si256(acc, _mm256_shuffle_epi32(acc, 0xB1));
    }

    __m128i vLow = _mm256_castsi256_si128(acc);
    __m128i vHigh = _mm256_extracti128_si256(acc, 1);
    __m128i tagFinal = _mm_xor_si128(vLow, vHigh);
    _mm_storeu_si128((__m128i*)tagOut, tagFinal);
}

Napi::Value BlazingOpossum::Encrypt(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (info.Length() < 2 || !info[0].IsTypedArray() || !info[1].IsTypedArray()) {
        Napi::TypeError::New(env, "Invalid arguments: expected (IV, Plaintext)").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    uint8_t* iv = info[0].As<Napi::Uint8Array>().Data();
    Napi::Uint8Array pt = info[1].As<Napi::Uint8Array>();
    size_t ptLen = pt.ByteLength();

    Napi::Uint8Array res = Napi::Uint8Array::New(env, ptLen + TagSize);
    
    ProcessCtrParallel(iv, pt.Data(), res.Data(), ptLen);
    ComputeTag(res.Data(), ptLen, iv, res.Data() + ptLen);
    
    return res;
}

Napi::Value BlazingOpossum::Decrypt(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 2 || !info[0].IsTypedArray() || !info[1].IsTypedArray()) {
        Napi::TypeError::New(env, "Invalid arguments: expected (IV, Ciphertext)").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    uint8_t* iv = info[0].As<Napi::Uint8Array>().Data();
    Napi::Uint8Array ctFull = info[1].As<Napi::Uint8Array>();
    
    if (ctFull.ByteLength() < TagSize) {
        Napi::Error::New(env, "Encrypted data is too short to contain a valid tag").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    size_t ctLen = ctFull.ByteLength() - TagSize;
    uint8_t* receivedTag = ctFull.Data() + ctLen;

    ALIGN32 uint8_t computedTag[TagSize];
    ComputeTag(ctFull.Data(), ctLen, iv, computedTag);

    int diff = 0;
    for(int i = 0; i < TagSize; i++) {
        diff |= (receivedTag[i] ^ computedTag[i]);
    }

    if (diff != 0) {
        Napi::Error::New(env, "Integrity Check Failed: potential tampering detected").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    Napi::Uint8Array res = Napi::Uint8Array::New(env, ctLen);
    ProcessCtrParallel(iv, ctFull.Data(), res.Data(), ctLen);
    
    return res;
}

Napi::Object InitAll(Napi::Env env, Napi::Object exports) {
    return BlazingOpossum::Init(env, exports);
}

NODE_API_MODULE(blazing_opossum, InitAll)