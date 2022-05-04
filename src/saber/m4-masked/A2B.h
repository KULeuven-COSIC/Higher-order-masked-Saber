#ifndef A2B
#define A2B

#include <stdint.h>
#include "SABER_params.h"
#include <stdlib.h>
#include <stddef.h>

/*
-------------------------------------------
       Higher order masking functions
-------------------------------------------
*/


void A2B_parallel_bitsliced(size_t nbits, uint16_t B[32][SABER_SHARES], const uint16_t A[32][SABER_SHARES]);
void SecAnd_high32(uint32_t z[SABER_SHARES], uint32_t x[SABER_SHARES], uint32_t y[SABER_SHARES]);

void A2B_keepbitsliced_B(uint32_t out[SABER_EP][SABER_SHARES][SABER_L][SABER_N/32], const uint16_t Bp[SABER_L][SABER_N][SABER_SHARES]);
void A2B_keepbitsliced_Cm(uint32_t out[SABER_ET][SABER_SHARES][SABER_N/32], const uint16_t Bp[SABER_N][SABER_SHARES]);
void A2B_bitsliced_msg(uint16_t msg[SABER_SHARES][SABER_N], const uint16_t vp[SABER_N][SABER_SHARES]);



#endif