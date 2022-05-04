#include "cbd-masked.h"
#include "masksONOFF.h"

#include <string.h>

/*
-------------------------------------------
       Higher order masking functions
-------------------------------------------
*/

void cbd_masked_HO(uint16_t s[SABER_SHARES][SABER_L][SABER_N], const uint8_t coins[SABER_SHARES][SABER_L * SABER_POLYCOINBYTES])
{
    int32_t i, j, k1, l;
    uint16_t temp1[4][SABER_SHARES],temp[4][SABER_SHARES];

    for (i = 0; i < SABER_L; i++) {
        for (j = 0; j < SABER_N/4; j++) {
            for (l = 0; l < SABER_SHARES; l++){
                temp[0][l] = coins[l][(i * SABER_POLYCOINBYTES)+ j]& 0x03;
                temp[1][l] = (coins[l][(i * SABER_POLYCOINBYTES)+ j] >> 2)& 0x03;
                temp[2][l] = (coins[l][(i * SABER_POLYCOINBYTES)+ j] >> 4)& 0x03;
                temp[3][l] = (coins[l][(i * SABER_POLYCOINBYTES)+ j] >> 6)& 0x03;
            }    
            for (k1 = 0; k1 < 4; k1 += 1) {   
                temp[k1][0] = temp[k1][0] ^ 2; 
                impconvBA(temp1[k1], temp[k1], SABER_SHARES);
                temp1[k1][0] = temp1[k1][0]- 2;
                for (l = 0; l < SABER_SHARES; l++)
                    s[l][i][4 * j + k1] = temp1[k1][l]; 
            }
        }    
    }
}
