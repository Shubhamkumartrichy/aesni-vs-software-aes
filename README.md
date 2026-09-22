# AESNI vs Software AES
---
A C++ implementation of a modified AES-128 cipher featuring both a conventional software implementation and an Intel AES-NI hardware-accelerated implementation, along with correctness verification and performance benchmarking.
---

## Contents

### Modified AES-128 vs. AES-NI

- Modified AES-128 key schedule
- Software AES encryption
- Software AES decryption
- Intel AES-NI encryption using hardware intrinsics
- Intel AES-NI decryption using hardware intrinsics
- Randomized correctness verification (1000 test cases)
- Throughput benchmarking (MB/s)
- CPU Cycles Per Byte (CPB) benchmarking using `__rdtsc()`

### GF(2³) Multiplication Table

- Polynomial multiplication over **GF(2)**
- Modular reduction using the irreducible polynomial

  P(x) = x³ + x + 1

- Generation of the complete **8 × 8 multiplication table**
- Binary and polynomial representation of field elements


