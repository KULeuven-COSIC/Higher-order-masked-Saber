#ifndef FIPS202_MASKED_H
#define FIPS202_MASKED_H

#include "SABER_params.h"
#include <stdint.h>
#include <stddef.h>
#include "masksONOFF.h"


#define NROUNDS 24

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE  72

#define ROL(a, offset) ((a << offset) ^ (a >> (64-offset)))

#ifndef ROTL64
#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))
#endif


void shake128_masked_HO(size_t outlen, uint8_t output[SABER_SHARES][outlen], size_t inlen, const uint8_t input[SABER_SHARES][inlen]);
void sha3_512_masked_HO(uint8_t output[SABER_SHARES][64], size_t inlen, const uint8_t input[SABER_SHARES][inlen]);

#endif