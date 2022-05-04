#ifndef POLY_H
#define POLY_H

#include "SABER_params.h"
#include "fips202.h"
#include <stdint.h>

void GenSecret(uint16_t s[SABER_L][SABER_N], uint8_t seed_s[SABER_NOISE_SEEDBYTES], int keypair);
void MatrixVectorMulKeyPair(uint8_t pk[SABER_INDCPA_PUBLICKEYBYTES], uint8_t sk[SABER_INDCPA_SECRETKEYBYTES]);

uint32_t MatrixVectorMulEnc(uint8_t ct0[SABER_POLYVECCOMPRESSEDBYTES], const uint8_t seed_A[SABER_SEEDBYTES], uint16_t sp[SABER_L][SABER_N], int compare);
uint32_t InnerProdEnc(uint8_t ciphertext[SABER_BYTES_CCA_DEC], const uint8_t pk[SABER_INDCPA_PUBLICKEYBYTES], uint16_t sp[SABER_L][SABER_N], const uint8_t m[SABER_KEYBYTES], int compare);
void InnerProdDec(uint8_t m[SABER_KEYBYTES], const uint8_t ciphertext[SABER_BYTES_CCA_DEC], const uint8_t sk[SABER_INDCPA_SECRETKEYBYTES]);

/*
-------------------------------------------
       Higher order masking functions
-------------------------------------------
*/

void GenSecret_masked_HO(uint16_t r[SABER_SHARES][SABER_L][SABER_N],const unsigned char seed[SABER_SHARES][SABER_NOISE_SEEDBYTES]);
void MatrixVectorMulEnc_masked_HO( uint16_t ct[SABER_SHARES][SABER_L][SABER_N], const uint8_t seed_A[SABER_SEEDBYTES], uint16_t sp[SABER_SHARES][SABER_L][SABER_N]);
void InnerProdEnc_masked_HO(uint16_t ct1[SABER_SHARES][SABER_N], const uint8_t pk[SABER_INDCPA_PUBLICKEYBYTES], uint16_t sp[SABER_SHARES][SABER_L][SABER_N], const uint8_t m[SABER_SHARES][SABER_KEYBYTES]);
void InnerProdDec_masked_HO(uint8_t m[SABER_SHARES][SABER_KEYBYTES], const uint8_t ciphertext[SABER_BYTES_CCA_DEC], uint16_t s[SABER_SHARES][SABER_L][SABER_N]);


#endif
