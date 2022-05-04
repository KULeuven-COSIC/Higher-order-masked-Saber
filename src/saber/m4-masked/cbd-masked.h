#ifndef CBD_MASKED_H
#define CBD_MASKED_H

#include "SABER_params.h"
#include <stdint.h>
#include "B2A.h"

void cbd_masked_HO(uint16_t s[SABER_SHARES][SABER_L][SABER_N], const uint8_t coins[SABER_SHARES][SABER_L * SABER_POLYCOINBYTES]);

#endif
