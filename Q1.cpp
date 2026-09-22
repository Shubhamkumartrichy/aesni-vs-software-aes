#include <bits/stdc++.h>
#include <immintrin.h>
#include <x86intrin.h>

using namespace std;

//============================================================
// AES S-Box
//============================================================
const uint8_t SBOX[256] = {
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,
0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,
0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,
0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,
0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,
0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,
0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,
0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,
0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,
0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,
0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,
0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,
0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,
0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,
0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,
0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,
0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

const uint8_t INV_SBOX[256] = {
0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,
0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,
0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,
0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,
0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,
0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,
0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,
0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,
0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,
0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,
0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,
0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,
0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,
0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,
0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,
0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,
0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D
};

//============================================================
// Modified Round Constants
//============================================================
const uint8_t RCON[10] = {
    0x01,0x02,0x04,0x08,0x10,
    0x20,0x40,0x80,0x1B,0x36
};

//============================================================
// ShiftRows byte permutation
//============================================================
const int SHIFT_ORDER[16] = {
     0, 5,10,15,
     4, 9,14, 3,
     8,13, 2, 7,
    12, 1, 6,11
};

const int INV_SHIFT_ORDER[16]={
    0,13,10,7,
    4,1,14,11,
    8,5,2,15,
    12,9,6,3
};

//============================================================
// ShiftRows for Key Schedule
//============================================================
void shiftRowsKey(uint8_t key[16])
{
    uint8_t temp[16];

    for(int i=0;i<16;i++)
        temp[i]=key[SHIFT_ORDER[i]];

    memcpy(key,temp,16);
}

//============================================================
// Modified Key Schedule
// roundKeys[0]=k(-1)
// roundKeys[10]=k9
//============================================================
void generateRoundKeys(const uint8_t masterKey[16],
                       uint8_t roundKeys[11][16])
{
    memcpy(roundKeys[0],masterKey,16);

    for(int round=1;round<=10;round++)
    {
        memcpy(roundKeys[round],roundKeys[round-1],16);

        shiftRowsKey(roundKeys[round]);

        roundKeys[round][0]^=RCON[round-1];
    }
}

//============================================================
// SubBytes
//============================================================
void subBytes(uint8_t state[16])
{
    for(int i=0;i<16;i++)
        state[i]=SBOX[state[i]];
}

void invSubBytes(uint8_t state[16])
{
    for(int i=0;i<16;i++)
        state[i]=INV_SBOX[state[i]];
}

//============================================================
// ShiftRows
//============================================================
void shiftRows(uint8_t state[16])
{
    uint8_t temp[16];

    for(int i=0;i<16;i++)
        temp[i]=state[SHIFT_ORDER[i]];

    memcpy(state,temp,16);
}

void invShiftRows(uint8_t state[16])
{
    uint8_t temp[16];

    for(int i=0;i<16;i++)
        temp[i]=state[INV_SHIFT_ORDER[i]];

    memcpy(state,temp,16);
}

//============================================================
// GF(2^8) Multiplication Helpers
//============================================================
uint8_t xtime(uint8_t x)
{
    if(x&0x80)
        return (x<<1)^0x1B;
    else
        return x<<1;
}

uint8_t mul2(uint8_t x)
{
    return xtime(x);
}

uint8_t mul3(uint8_t x)
{
    return xtime(x)^x;
}

uint8_t mul9(uint8_t x)
{
    return xtime(xtime(xtime(x))) ^ x;
}

uint8_t mul11(uint8_t x)
{
    return xtime(xtime(xtime(x))) ^ xtime(x) ^ x;
}

uint8_t mul13(uint8_t x)
{
    return xtime(xtime(xtime(x))) ^ xtime(xtime(x)) ^ x;
}

uint8_t mul14(uint8_t x)
{
    return xtime(xtime(xtime(x))) ^
           xtime(xtime(x)) ^
           xtime(x);
}

//============================================================
// MixColumns
//============================================================
void mixColumns(uint8_t state[16])
{
    for(int c=0;c<4;c++)
    {
        int i=4*c;

        uint8_t a0=state[i];
        uint8_t a1=state[i+1];
        uint8_t a2=state[i+2];
        uint8_t a3=state[i+3];

        state[i]   = mul2(a0)^mul3(a1)^a2^a3;
        state[i+1] = a0^mul2(a1)^mul3(a2)^a3;
        state[i+2] = a0^a1^mul2(a2)^mul3(a3);
        state[i+3] = mul3(a0)^a1^a2^mul2(a3);
    }
}

void invMixColumns(uint8_t state[16])
{
    for(int c=0;c<4;c++)
    {
        int i=4*c;

        uint8_t a0=state[i];
        uint8_t a1=state[i+1];
        uint8_t a2=state[i+2];
        uint8_t a3=state[i+3];

        state[i]   = mul14(a0)^mul11(a1)^mul13(a2)^mul9(a3);
        state[i+1] = mul9(a0)^mul14(a1)^mul11(a2)^mul13(a3);
        state[i+2] = mul13(a0)^mul9(a1)^mul14(a2)^mul11(a3);
        state[i+3] = mul11(a0)^mul13(a1)^mul9(a2)^mul14(a3);
    }
}

//============================================================
// AddRoundKey
//============================================================
void addRoundKey(uint8_t state[16],const uint8_t key[16])
{
    for(int i=0;i<16;i++)
        state[i]^=key[i];
}

//============================================================
// Print Utility
//============================================================
void printState(const uint8_t state[16])
{
    for(int i=0;i<16;i++)
        cout<<hex<<setw(2)<<setfill('0')
            <<(int)state[i]<<" ";

    cout<<dec<<endl;
}

//============================================================
// Software AES Encryption
//============================================================
void encrypt_sw(const uint8_t plaintext[16],
                uint8_t ciphertext[16],
                const uint8_t roundKeys[11][16])
{
    uint8_t state[16];

    // Copy plaintext into working state
    memcpy(state, plaintext, 16);

    // Initial AddRoundKey with k(-1)
    addRoundKey(state, roundKeys[0]);

    // Rounds 1-9 (use k0 to k8)
    for(int round = 1; round <= 9; round++)
    {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, roundKeys[round]);
    }

    // Final Round (use k9, no MixColumns)
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, roundKeys[10]);

    // Copy result to output
    memcpy(ciphertext, state, 16);
}

void decrypt_sw(const uint8_t ciphertext[16],
                uint8_t plaintext[16],
                const uint8_t roundKeys[11][16])
{
    uint8_t state[16];

    memcpy(state, ciphertext, 16);

    // Step 1: AddRoundKey with k9
    addRoundKey(state, roundKeys[10]);

    // Rounds 9 → 1
    for(int round = 9; round >= 1; round--)
    {
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, roundKeys[round]);
        invMixColumns(state);
    }

    // Final step: InvShiftRows → InvSubBytes → AddRoundKey with k(-1)
    invShiftRows(state);
    invSubBytes(state);
    addRoundKey(state, roundKeys[0]);

    memcpy(plaintext, state, 16);
}

//============================================================
// Generate Modified Round Keys using AES-NI
// k_i = ShiftRows(k_{i-1}) XOR RC_i
//============================================================
void generateRoundKeysAESNI(const uint8_t masterKey[16], __m128i aesKeys[11])
{
    // k0 = Master Key
    aesKeys[0] = _mm_loadu_si128((const __m128i*)masterKey);

    // ShiftRows permutation mask
    const __m128i shiftrows_mask = _mm_setr_epi8(
         0,  5, 10, 15,
         4,  9, 14,  3,
         8, 13,  2,  7,
        12,  1,  6, 11
    );

    for (int round = 1; round <= 10; round++)
    {
        __m128i shifted = _mm_shuffle_epi8(aesKeys[round - 1], shiftrows_mask);

        __m128i rc = _mm_setr_epi8(
            RCON[round - 1],
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0
        );

        aesKeys[round] = _mm_xor_si128(shifted, rc);
    }
}


//============================================================
// AES-NI Encryption
//============================================================
void encrypt_aesni(const uint8_t plaintext[16],
                   uint8_t ciphertext[16],
                   const __m128i aesKeys[11])
{
    __m128i state = _mm_loadu_si128((const __m128i*)plaintext);

    // Initial AddRoundKey with k0
    state = _mm_xor_si128(state, aesKeys[0]);

    // Rounds 1-9
    for (int round = 1; round <= 9; round++)
        state = _mm_aesenc_si128(state, aesKeys[round]);

    // Final Round
    state = _mm_aesenclast_si128(state, aesKeys[10]);

    _mm_storeu_si128((__m128i*)ciphertext, state);
}


//============================================================
// Generate AES-NI Decryption Keys
//============================================================
void generateDecryptKeysAESNI(const __m128i encKeys[11],
                              __m128i decKeys[11])
{
    // First and last keys are used directly
    decKeys[0]  = encKeys[10];
    decKeys[10] = encKeys[0];

    // Middle keys need AESIMC
    for(int i=1;i<=9;i++)
    {
        decKeys[i] = _mm_aesimc_si128(encKeys[10-i]);
    }
}

//============================================================
// AES-NI Decryption
//============================================================
void decrypt_aesni(const uint8_t ciphertext[16],
                   uint8_t plaintext[16],
                   const __m128i decKeys[11])
{
    __m128i state =_mm_loadu_si128((const __m128i*)ciphertext);

    // Initial AddRoundKey
    state = _mm_xor_si128(state, decKeys[0]);

    // Rounds 1-9
    for(int round=1; round<=9; round++)
    {
        state = _mm_aesdec_si128(state, decKeys[round]);
    }

    // Final Round
    state = _mm_aesdeclast_si128(state, decKeys[10]);

    _mm_storeu_si128((__m128i*)plaintext, state);
}

//============================================================
// Randomized Correctness Test
//============================================================
void randomizedCorrectnessTest(int tests = 1000)
{
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<int> dist(0, 255);

    int passed = 0;

    for(int t = 0; t < tests; t++)
    {
        uint8_t masterKey[16];
        uint8_t plaintext[16];

        // Generate random key and plaintext
        for(int i = 0; i < 16; i++)
        {
            masterKey[i] = dist(gen);
            plaintext[i] = dist(gen);
        }

        // Software variables
        uint8_t roundKeys[11][16];
        uint8_t swCipher[16];
        uint8_t swRecovered[16];

        // AES-NI variables
        __m128i aesKeys[11];
        __m128i decKeys[11];
        uint8_t aesCipher[16];
        uint8_t aesRecovered[16];

        // Generate keys
        generateRoundKeys(masterKey, roundKeys);
        generateRoundKeysAESNI(masterKey, aesKeys);
        generateDecryptKeysAESNI(aesKeys, decKeys);

        // Software encryption/decryption
        encrypt_sw(plaintext, swCipher, roundKeys);
        decrypt_sw(swCipher, swRecovered, roundKeys);

        // AES-NI encryption/decryption
        encrypt_aesni(plaintext, aesCipher, aesKeys);
        decrypt_aesni(aesCipher, aesRecovered, decKeys);

        // Verify all four conditions
        bool ok =
            memcmp(plaintext, swRecovered, 16) == 0 &&
            memcmp(plaintext, aesRecovered, 16) == 0 &&
            memcmp(swCipher, aesCipher, 16) == 0 &&
            memcmp(swRecovered, aesRecovered, 16) == 0;

        if(ok)
            passed++;
        else
        {
            cout << "\nRandomized test failed at iteration "
                 << t + 1 << "!\n";

            cout << "Master Key:\n";
            printState(masterKey);

            cout << "Plaintext:\n";
            printState(plaintext);

            cout << "Software Ciphertext:\n";
            printState(swCipher);

            cout << "AES-NI Ciphertext:\n";
            printState(aesCipher);

            return;
        }
    }

    cout << "\n=========================================\n";
    cout << "Randomized Correctness Test: "
         << passed << "/" << tests
         << " PASSED\n";
    cout << "=========================================\n";
}

//============================================================
// Benchmark Result
//============================================================
struct BenchmarkResult
{
    double throughputMBps;
    double cyclesPerByte;
};

//============================================================
// Software Benchmark
//============================================================
BenchmarkResult benchmarkSoftware(
    void (*operation)(const uint8_t*, uint8_t*, const uint8_t (*)[16]),
    const vector<uint8_t>& input,
    vector<uint8_t>& output,
    const uint8_t roundKeys[11][16],
    int repetitions = 20)
{
    double totalTime = 0.0;
    double totalCPB = 0.0;

    for(int rep = 0; rep < repetitions; rep++)
    {
        auto startTime = chrono::high_resolution_clock::now();
        uint64_t startCycles = __rdtsc();

        for(size_t i = 0; i < input.size(); i += 16)
            operation(&input[i], &output[i], roundKeys);

        uint64_t endCycles = __rdtsc();
        auto endTime = chrono::high_resolution_clock::now();

        double seconds =
            chrono::duration<double>(endTime - startTime).count();

        totalTime += seconds;
        totalCPB +=
            (double)(endCycles - startCycles) / input.size();
    }

    double avgTime = totalTime / repetitions;

    BenchmarkResult result;
    result.throughputMBps =
        (input.size() / (1024.0 * 1024.0)) / avgTime;
    result.cyclesPerByte =
        totalCPB / repetitions;

    return result;
}

//============================================================
// AES-NI Benchmark
//============================================================
BenchmarkResult benchmarkAESNI(
    void (*operation)(const uint8_t*, uint8_t*, const __m128i*),
    const vector<uint8_t>& input,
    vector<uint8_t>& output,
    const __m128i keys[11],
    int repetitions = 20)
{
    double totalTime = 0.0;
    double totalCPB = 0.0;

    for(int rep = 0; rep < repetitions; rep++)
    {
        auto startTime = chrono::high_resolution_clock::now();
        uint64_t startCycles = __rdtsc();

        for(size_t i = 0; i < input.size(); i += 16)
            operation(&input[i], &output[i], keys);

        uint64_t endCycles = __rdtsc();
        auto endTime = chrono::high_resolution_clock::now();

        double seconds =
            chrono::duration<double>(endTime - startTime).count();

        totalTime += seconds;
        totalCPB +=
            (double)(endCycles - startCycles) / input.size();
    }

    double avgTime = totalTime / repetitions;

    BenchmarkResult result;
    result.throughputMBps =
        (input.size() / (1024.0 * 1024.0)) / avgTime;
    result.cyclesPerByte =
        totalCPB / repetitions;

    return result;
}


//============================================================
// Run Performance Benchmarks
//============================================================
void runBenchmarks()
{
    vector<size_t> sizes = {
        1024,
        2048,
        4096,
        32768,
        65536
    };

    uint8_t masterKey[16] = {0};

    // Generate keys BEFORE timing
    uint8_t roundKeys[11][16];
    generateRoundKeys(masterKey, roundKeys);

    __m128i aesKeys[11];
    generateRoundKeysAESNI(masterKey, aesKeys);

    __m128i decKeys[11];
    generateDecryptKeysAESNI(aesKeys, decKeys);

    cout << "\n====================================================================\n";
    cout << "             PERFORMANCE BENCHMARK (Average of 20 Runs)\n";
    cout << "====================================================================\n\n";

    // Reset fill character (printState() leaves it as '0')
    cout << left << setfill(' ');

    cout << setw(8)  << "Size"
         << setw(18) << "Implementation"
         << setw(22) << "Throughput (MB/s)"
         << setw(16) << "CPB"
         << '\n';

    cout << string(64, '-') << '\n';

    for (size_t bytes : sizes)
    {
        vector<uint8_t> input(bytes);
        vector<uint8_t> output(bytes);

        for (size_t i = 0; i < bytes; i++)
            input[i] = i & 0xFF;

        auto swEnc = benchmarkSoftware(
            encrypt_sw,
            input,
            output,
            roundKeys);

        auto swDec = benchmarkSoftware(
            decrypt_sw,
            output,
            input,
            roundKeys);

        auto aesEnc = benchmarkAESNI(
            encrypt_aesni,
            input,
            output,
            aesKeys);

        auto aesDec = benchmarkAESNI(
            decrypt_aesni,
            output,
            input,
            decKeys);

        auto printRow = [&](const string& op, const BenchmarkResult& r)
        {
            cout << left << setfill(' ')
                 << setw(8)  << (to_string(bytes / 1024) + " KB")
                 << setw(18) << op
                 << setw(22) << fixed << setprecision(2) << r.throughputMBps
                 << setw(16) << fixed << setprecision(2) << r.cyclesPerByte
                 << '\n';
        };

        printRow("SW Encrypt",  swEnc);
        printRow("AES Encrypt", aesEnc);
        printRow("SW Decrypt",  swDec);
        printRow("AES Decrypt", aesDec);

        cout << string(64, '-') << '\n';
    }
}


//============================================================
// Main
//============================================================
int main()
{
    // --------------------------------------------------------
    // Test Inputs
    // --------------------------------------------------------
    uint8_t masterKey[16] = {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F
    };

    uint8_t plaintext[16] = {
        0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB,
        0xCC, 0xDD, 0xEE, 0xFF
    };

    // --------------------------------------------------------
    // Software AES Variables
    // --------------------------------------------------------
    uint8_t roundKeys[11][16];
    uint8_t ciphertext[16];
    uint8_t recovered[16];

    // --------------------------------------------------------
    // AES-NI Variables
    // --------------------------------------------------------
    __m128i aesKeys[11];
    __m128i decKeys[11];
    uint8_t aesCipher[16];
    uint8_t aesRecovered[16];

    //=========================================================
    // Software AES
    //=========================================================

    // Generate modified round keys
    generateRoundKeys(masterKey, roundKeys);

    // Encrypt
    encrypt_sw(plaintext, ciphertext, roundKeys);

    // Decrypt
    decrypt_sw(ciphertext, recovered, roundKeys);

    // Display results
    cout << "================ SOFTWARE AES ================\n";

    cout << "\nMaster Key:\n";
    printState(masterKey);

    cout << "\nPlaintext:\n";
    printState(plaintext);

    cout << "\nCiphertext:\n";
    printState(ciphertext);

    cout << "\nRecovered Plaintext:\n";
    printState(recovered);

    if (memcmp(plaintext, recovered, 16) == 0)
        cout << "\nSoftware AES: SUCCESS\n";
    else
        cout << "\nSoftware AES: FAILED\n";

    //=========================================================
    // AES-NI
    //=========================================================

    // AES-NI Key Generation
    generateRoundKeysAESNI(masterKey, aesKeys);

    // Encrypt using AES-NI
    encrypt_aesni(plaintext, aesCipher, aesKeys);

    cout << "\n================== AES-NI ==================\n";

    cout << "\nAES-NI Ciphertext:\n";
    printState(aesCipher);

    // Verify software vs AES-NI encryption
    if (memcmp(ciphertext, aesCipher, 16) == 0)
        cout << "\nSoftware and AES-NI ciphertext MATCH.\n";
    else
        cout << "\nSoftware and AES-NI ciphertext MISMATCH.\n";

    // AES-NI Decryption
    generateDecryptKeysAESNI(aesKeys, decKeys);

    decrypt_aesni(aesCipher, aesRecovered, decKeys);

    cout << "\nAES-NI Recovered Plaintext:\n";
    printState(aesRecovered);

    // Verify AES-NI decryption
    if (memcmp(plaintext, aesRecovered, 16) == 0)
        cout << "\nAES-NI Decryption: SUCCESS\n";
    else
        cout << "\nAES-NI Decryption: FAILED\n";

    // Randomized Correctness Testing
    randomizedCorrectnessTest(1000);

    // Performance Benchmark
    runBenchmarks();

    return 0;
}