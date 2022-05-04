#ifndef VERIFY_H
#define VERIFY_H

#include "SABER_params.h"
#include "fips202.h"
#include <stddef.h>
#include <stdint.h>
#include "masksONOFF.h"
#include <string.h>
#include <stdio.h>
#include <stdbool.h>



/* b = 1 means mov, b = 0 means don't mov*/
void cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b);

/*
-------------------------------------------
       Higher order masking functions
-------------------------------------------
*/

/* returns 1 for equal strings, 0 for non-equal strings */
void masked_comparison_simple(uint8_t b[SABER_SHARES],uint16_t u[SABER_SHARES][SABER_L][SABER_N],uint16_t v[SABER_SHARES][SABER_N],uint16_t u_prime[SABER_L][SABER_N],uint16_t v_prime[SABER_N]);

#endif
