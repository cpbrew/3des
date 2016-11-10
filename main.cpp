#include <iostream>
#include <string.h>
#include <cryptopp/sha.h>
#include <fstream>
#include <iomanip>
#include <bitset>

using namespace std;

void genkey(const char *, const char *);
void encrypt(uint64_t *, size_t, uint64_t);
void decrypt(uint64_t *, size_t, uint64_t);

uint64_t *deriveRoundKeys(uint64_t);
uint64_t permutate(uint64_t, int, const int *, int);
uint64_t runDes(uint64_t *, uint64_t);
uint32_t roundFunc(uint32_t, uint64_t);
uint32_t sbox(uint64_t);

void readKeys(const char *, uint64_t *);
void usage(const char *);
uint64_t rotr(uint64_t, size_t, unsigned int);
uint64_t rotl(uint64_t, size_t, unsigned int);
void btol(uint8_t *, uint64_t *);
void ltob(uint64_t, uint8_t *);
void printNumberedBits(uint64_t, size_t);
template <typename T>
void reverseArray(T *, size_t);
void byteArrayToLongArray(uint8_t *, uint64_t *, size_t bytes);
void longArrayToByteArray(uint64_t *, uint8_t *, size_t bytes);

// How many bits the key schedule state is rotated each round
const int KS[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

// Initial permutation
const int IP[64] = {58, 50, 42, 34, 26, 18, 10,  2,
                    60, 52, 44, 36, 28, 20, 12,  4,
                    62, 54, 46, 38, 30, 22, 14,  6,
                    64, 56, 48, 40, 32, 24, 16,  8,
                    57, 49, 41, 33, 25, 17,  9,  1,
                    59, 51, 43, 35, 27, 19, 11,  3,
                    61, 53, 45, 37, 29, 21, 13,  5,
                    63, 55, 47, 39, 31, 23, 15,  7
                   };

// Final permutation
const int FP[64] = {40,  8, 48, 16, 56, 24, 64, 32,
                    39,  7, 47, 15, 55, 23, 63, 31,
                    38,  6, 46, 14, 54, 22, 62, 30,
                    37,  5, 45, 13, 53, 21, 61, 29,
                    36,  4, 44, 12, 52, 20, 60, 28,
                    35,  3, 43, 11, 51, 19, 59, 27,
                    34,  2, 42, 10, 50, 18, 58, 26,
                    33,  1, 41,  9, 49, 17, 57, 25
                   };

// Permuted choice 2
const int PC2[48] = {14, 17, 11, 24,  1,  5,
                      3, 28, 15,  6, 21, 10,
                     23, 19, 12,  4, 26,  8,
                     16,  7, 27, 20, 13,  2,
                     41, 52, 31, 37, 47, 55,
                     30, 40, 51, 45, 33, 48,
                     44, 49, 39, 56, 34, 53,
                     46, 42, 50, 36, 29, 32
                    };

// Expansion function
const int EP[48] = {32,  1,  2,  3,  4,  5,
                     4,  5,  6,  7,  8,  9,
                     8,  9, 10, 11, 12, 13,
                    12, 13, 14, 15, 16, 17,
                    16, 17, 18, 19, 20, 21,
                    20, 21, 22, 23, 24, 25,
                    24, 25, 26, 27, 28, 29,
                    28, 29, 30, 31, 32,  1
                   };

// The core of DES
const int SBOXES[8][4][16] = {
    {
        {14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
        { 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
        { 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
        {15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13}
    },
    {   {15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10},
        { 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
        { 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
        {13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9}
    },
    {   {10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
        {13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
        {13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
        { 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12}
    },
    {   { 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15},
        {13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9},
        {10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4},
        { 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14}
    },
    {   { 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9},
        {14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6},
        { 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14},
        {11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3}
    },
    {   {12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11},
        {10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8},
        { 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6},
        { 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13}
    },
    {   { 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1},
        {13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6},
        { 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2},
        { 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12}
    },
    {   {13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7},
        { 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2},
        { 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8},
        { 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11}
    }
};

// Round permutation
const int P[32] = {16,  7, 20, 21,
                   29, 12, 28, 17,
                    1, 15, 23, 26,
                    5, 18, 31, 10,
                    2,  8, 24, 14,
                   32, 27,  3,  9,
                   19, 13, 30,  6,
                   22, 11,  4, 25
                  };

int main(int argc, char *argv[])
{
    uint64_t keys[3];
    uint64_t *data;
    uint8_t *buffer;
    fstream f;
    size_t fileSize;
    unsigned int padding;

    if (argc < 4)
    {
        usage(argv[0]);
    }
    if (strcmp("genkey", argv[1]) == 0)
    {
        if (argc != 4)
        {
            usage(argv[0]);
        }
        else
        {
            genkey(argv[2], argv[3]);
            return 0;
        }
    }
    if (strcmp("encrypt", argv[1]) == 0)
    {
        if (argc != 6)
        {
            usage(argv[0]);
        }

        readKeys(argv[3], keys);

        f.open(argv[2], ios::in | ios::binary | ios::ate);
        fileSize = f.tellg();
        padding = 8 - (fileSize % 8);
        f.seekg(0, ios::beg);

        buffer = new uint8_t[fileSize + padding];
        f.read((char *)buffer, fileSize);
        f.close();

        for (unsigned int i = 0; i < padding; i++)
        {
            buffer[fileSize + i] = (uint8_t) padding;
        }

        data = new uint64_t[((fileSize + padding) / 8)];
        byteArrayToLongArray(buffer, data, fileSize + padding);

        encrypt(data, (fileSize + padding) / 8, keys[0]);
        decrypt(data, (fileSize + padding) / 8, keys[1]);
        encrypt(data, (fileSize + padding) / 8, keys[2]);

        longArrayToByteArray(data, buffer, fileSize + padding);

        f.open(argv[4], ios::out | ios::binary);
        f.write((const char *)buffer, fileSize + padding);
        f.close();
    }
    else if (strcmp("decrypt", argv[1]) == 0)
    {
        if (argc != 6)
        {
            usage(argv[0]);
        }

        readKeys(argv[3], keys);

        f.open(argv[2], ios::in | ios::binary | ios::ate);
        fileSize = f.tellg();
        f.seekg(0, ios::beg);

        buffer = new uint8_t[fileSize];
        f.read((char *)buffer, fileSize);
        f.close();

        data = new uint64_t[fileSize / 8];
        byteArrayToLongArray(buffer, data, fileSize);

        decrypt(data, fileSize / 8, keys[2]);
        encrypt(data, fileSize / 8, keys[1]);
        decrypt(data, fileSize / 8, keys[0]);

        longArrayToByteArray(data, buffer, fileSize);
        padding = buffer[fileSize - 1];

        f.open(argv[4], ios::out | ios::binary);
        f.write((const char *)buffer, fileSize - padding);
        f.close();
    }

    return 0;
}

void genkey(const char *password, const char *keyFile)
{
    char digest[CryptoPP::SHA256::DIGESTSIZE];
    ofstream out(keyFile, ios::out | ios::binary);

    CryptoPP::SHA256().CalculateDigest((byte *)digest, (byte *)password, strlen(password));
    out.write((char *)digest, 7);

    for (unsigned int i = 0; i < CryptoPP::SHA256::DIGESTSIZE && i < strlen(password); i++)
        digest[i] ^= password[i];

    CryptoPP::SHA256().CalculateDigest((byte *)digest, (byte *)digest, CryptoPP::SHA256::DIGESTSIZE);
    out.write((char *)digest, 7);

    for (unsigned int i = 0; i < CryptoPP::SHA256::DIGESTSIZE && i < strlen(password); i++)
        digest[i] ^= password[i];

    CryptoPP::SHA256().CalculateDigest((byte *)digest, (byte *)digest, CryptoPP::SHA256::DIGESTSIZE);
    out.write((char *)digest, 7);

    out.close();
}

void encrypt(uint64_t *data, size_t blocks, uint64_t key)
{
        uint64_t *roundKeys = deriveRoundKeys(key);
        for (unsigned int i = 0; i < blocks; i++)
        {
            data[i] = runDes(roundKeys, data[i]);
        }
}

void decrypt(uint64_t *data, size_t blocks, uint64_t key)
{
        uint64_t *roundKeys = deriveRoundKeys(key);
        reverseArray(roundKeys, 16);
        for (unsigned int i = 0; i < blocks; i++)
        {
            data[i] = runDes(roundKeys, data[i]);
        }
}

uint64_t runDes(uint64_t *roundKeys, uint64_t block)
{
    block = permutate(block, 64, IP, 64);

    uint32_t l = (uint32_t) (block >> 32),
             r = (uint32_t) (block & 0xFFFFFFFF),
             tmp;

    for (int i = 0; i < 16; i++)
    {
        tmp = l;
        l = r;
        r = tmp ^ roundFunc(r, roundKeys[i]);
    }
    block = (((uint64_t) r) << 32) | (((uint64_t) l) & 0x00000000FFFFFFFFl);
    block = permutate(block, 64, FP, 64);

    return block;
}

uint32_t roundFunc(uint32_t data, uint64_t key)
{
    uint64_t x = permutate(((uint64_t) data) & 0x00000000FFFFFFFFl, 32, EP, 48);
    x ^= key;
    data = sbox(x);
    return (uint32_t) permutate((uint64_t) data, 32, P, 32);
}

uint32_t sbox(uint64_t data)
{
    uint32_t output = 0;
    uint32_t row, column;
    uint64_t bits;
    uint64_t mask = 0x3F000000000000l;

    for (int i = 0; i < 8; i++)
    {
        mask >>= 6;
        bits = data & mask;
        bits >>= (6 * (8 - (i + 1)));

        row = (uint32_t) (bits & 1l);
        bits >>= 1;
        column = (uint32_t) (bits & 0xFl);
        bits >>= 3;
        row |= (uint32_t) (bits & 0x2l);

        output <<= 4;
        output |= SBOXES[i][row][column];
    }

    return output;
}

uint64_t *deriveRoundKeys(uint64_t key)
{
    const uint64_t LEFT_MASK = 0x00FFFFFFF0000000l;
    const uint64_t RIGHT_MASK = 0x000000000FFFFFFFl;
    uint64_t *keys = new uint64_t[16];
    uint32_t c = (uint32_t) ((key & LEFT_MASK) >> 28);
    uint32_t d = (uint32_t) (key & RIGHT_MASK);

    for (int i = 0; i < 16; i++)
    {
        c = rotl(c, 28, KS[i]);
        d = rotl(d, 28, KS[i]);
        key = ((((uint64_t) c) << 28) & LEFT_MASK) | (d & RIGHT_MASK);
        keys[i] = permutate(key, 56, PC2, 48);
    }

    return keys;
}

uint64_t permutate(uint64_t bits, int bitLength, const int *permutation, int permLength)
{
    uint64_t output = 0;
    uint64_t mask = rotl(1l, 64, bitLength);

    for (int i = 0; i < permLength; i++)
    {
        if ((rotr(mask, 64, permutation[i]) & bits) > 0)
        {
            output |= 1l << (permLength - 1 - i);
        }
    }

    return output;
}

void readKeys(const char *keyFile, uint64_t *keys)
{
    ifstream in(keyFile, ios::in | ios::binary);
    for (int i = 0; i < 3; i++)
        in.read((char *)&(keys[i]), 7);
    in.close();
}

uint64_t rotr(uint64_t bits, size_t width, unsigned int n)
{
    uint64_t mask;
    if (width == 64)
    {
        // special case: apparently << is a circular shift (at least in g++),
        // meaning that 1 << 64 = 1 instead of 0. would prefer to avoid this
        // behavior rather than rely on it
        mask = -1;
    }
    else
    {
        mask = (1l << width) - 1;
    }
    return (bits >> n) | ((bits << (width - n)) & mask);
}

uint64_t rotl(uint64_t bits, size_t width, unsigned int n)
{
    uint64_t mask;
    if (width == 64)
    {
        // special case: see above
        mask = -1;
    }
    else
    {
        mask = (1l << width) - 1;
    }
    return (bits << n) | ((bits >> (width - n)) & mask);
}

void btol(uint8_t *b, uint64_t *l)
{
    *l = 0l;
    for (int i = 0; i < 8; i++)
    {
        *l <<= 8;
        *l |= b[i];
    }
}

void ltob(uint64_t l, uint8_t *b)
{
    for (int i = 7; i >= 0; i--)
    {
        b[i] = (uint8_t) (l & 0xFF);
        l >>= 8;
    }
}

void usage(const char *name)
{
    cout << "Usage:" << endl;
    cout << name << " genkey password keyFile" << endl;
    cout << name << " encrypt inputFile keyFile outputFile mode" << endl;
    cout << name << " decrypt inputFile keyFile outputFile mode" << endl;

    exit(1);
}

void printNumberedBits(uint64_t data, size_t numBits)
{
    for (unsigned int i = 0; i < numBits; i++)
    {
        cout << setw(2) << setfill('0') << (i + 1) << " ";
    }
    cout << endl;
    uint64_t mask = rotl(1l, 64, numBits);
    for (unsigned int i = 0; i < numBits; i++)
    {
        mask = rotr(mask, 64, 1);
        if ((mask & data) > 0)
        {
            cout << " 1 ";
        }
        else
        {
            cout << " 0 ";
        }
    }
    cout << endl;
}

template <typename T>
void reverseArray(T *arr, size_t n)
{
    T tmp;
    for (unsigned int i = 0; i < (n / 2); i++)
    {
        tmp = arr[i];
        arr[i] = arr[n - i - 1];
        arr[n - i - 1] = tmp;
    }
}

void byteArrayToLongArray(uint8_t *charArr, uint64_t *longArr, size_t bytes)
{
    for (unsigned int i = 0; i < bytes; i += 8)
    {
        btol(&(charArr[i]), &(longArr[i / 8]));
    }
}

void longArrayToByteArray(uint64_t *longArr, uint8_t *charArr, size_t bytes)
{
    for (unsigned int i = 0; i < bytes; i += 8)
    {
        ltob(longArr[i / 8], &(charArr[i]));
    }
}
