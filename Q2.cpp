#include <bits/stdc++.h>
using namespace std;

// GF(2^3) with irreducible polynomial P(x) = x^3 + x + 1
// Reduction rule: x^3 = x + 1, so XOR with 0b011 when degree reaches 3

uint8_t gf8_mul(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    for (int i = 0; i < 3; i++) {
        if (b & 1)
            result ^= a;
        b >>= 1;
        uint8_t carry = a & 0x4;   // x^2 bit will become x^3 after shift
        a = (a << 1) & 0x7;        // shift left, keep only 3 bits
        if (carry)
            a ^= 0x3;              // reduce: x^3 mod P(x) = x+1 = 011
    }
    return result;
}

int main() {
    cout << "Multiplication Table of GF(2^3) = F2[x]/(x^3 + x + 1)\n\n";

    cout << "  x |";
    for (int j = 0; j < 8; j++)
        cout << setw(3) << j;
    cout << "\n ---+";
    for (int j = 0; j < 8; j++)
        cout << "---";
    cout << "\n";

    for (int i = 0; i < 8; i++) {
        cout << setw(3) << i << " |";
        for (int j = 0; j < 8; j++)
            cout << setw(3) << (int)gf8_mul(i, j);
        cout << "\n";
    }
    return 0;
}