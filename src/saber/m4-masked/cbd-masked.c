#include "cbd-masked.h"
#include "masksONOFF.h"

#include <string.h>

#define kappa 4
#define lambda 4

/*
-------------------------------------------
       Higher order masking functions
-------------------------------------------
*/

static void SecAnd_higher_order(uint32_t x[SABER_SHARES], uint32_t y[SABER_SHARES])
{
    uint32_t i,j,r[SABER_SHARES][SABER_SHARES];
    uint32_t z[SABER_SHARES];
    uint32_t rand;
    
    for(i=0;i<SABER_SHARES;i++)
    	z[i]=x[i]&y[i];
    for(i=0;i<(SABER_SHARES-1);i++)
    {
    	for(j=(i+1);j<SABER_SHARES;j++)
    	{
    		rand= random_uint32();
    		r[i][j]=rand;
    		r[j][i]=(r[i][j]^(x[i]&y[j])^(x[j]&y[i]));
    		z[i]=z[i]^r[i][j];
    		z[j]=z[j]^r[j][i];
    	}
    }
    
    for(i=0;i<SABER_SHARES;i++)
    	x[i]=z[i];

}

static void SecBitAdd_HO(uint32_t x_bit[SABER_SHARES][kappa], uint32_t z[SABER_SHARES][lambda])
{

    size_t j, k1, l, i;
    uint32_t w[SABER_SHARES], u[SABER_SHARES];

    //initialize
    for (j = 0; j < lambda; j++)
    {
    	for (i = 0; i < SABER_SHARES; i++)
    	{
    		z[i][j]=0;
    	}
    }

    for (j = 0; j < kappa; j++) {
    	for (i = 0; i < SABER_SHARES; i++){
    		u[i] = z[i][0];
    		w[i] = x_bit[i][j];
    		z[i][0] = u[i] ^ w[i];
    	}

        l = 1;
        k1 = j + 1;

        while (k1 >>= 1) {

            SecAnd_higher_order(w, u);
            
            for (i = 0; i < SABER_SHARES; i++){
            	u[i] = z[i][l];
            	z[i][l] = z[i][l] ^ w[i];
            }

            l++;
        }
    }
}

static void SecBitSub_HO(uint32_t y_bit[SABER_SHARES][kappa], uint32_t z[SABER_SHARES][lambda])
{

    int32_t i, j, l;
    uint32_t w[SABER_SHARES], u[SABER_SHARES];

    for (j = 0; j < kappa; j++) {
    
    	for (i = 0; i < SABER_SHARES; i++){
		w[i] = y_bit[i][j];}

        for (l = 0; l < lambda; l++) {
        
	    for (i = 0; i < SABER_SHARES; i++){
	    	u[i] = z[i][l];
            	z[i][l] = u[i] ^ w[i];}
	    
            u[0] = ~u[0];

            SecAnd_higher_order(w, u);
        }
    }
}

static void SecConsAdd_HO(uint32_t y_bit[SABER_SHARES][lambda])  //adds kappa //optimized for kappa=4
{
    uint32_t i;
    
    for(i=0;i<SABER_SHARES;i++) 
    	y_bit[i][3] = y_bit[i][3] ^ y_bit[i][2];
    y_bit[0][2] = y_bit[0][2] ^ 0xffffffff;

}

static void SecBitAddBitSubConsAdd_HO(uint32_t x_bit[SABER_SHARES][kappa], uint32_t y_bit[SABER_SHARES][kappa], uint32_t z_bit[SABER_SHARES][lambda])
{
    SecBitAdd_HO(x_bit, z_bit);
    SecBitSub_HO(y_bit, z_bit);
    SecConsAdd_HO(z_bit);
}


static void pack_bitslice_HO(uint32_t x[kappa], uint32_t y[kappa], const uint8_t coins[(SABER_MU*SABER_N/8)])
{
    int i;
    uint32_t x_bit[kappa] = {0};
    uint32_t y_bit[kappa] = {0};

    for (i = 0; i < 32; i++) {

        x_bit[0] = x_bit[0] | (( coins[i] & 0x01 ) << i );
        x_bit[1] = x_bit[1] | (( (coins[i] >> 1) & 0x01 ) << i );
        x_bit[2] = x_bit[2] | (( (coins[i] >> 2) & 0x01 ) << i );
        x_bit[3] = x_bit[3] | (( (coins[i] >> 3) & 0x01 ) << i );

        y_bit[0] = y_bit[0] | (( (coins[i] >> 4) & 0x01 ) << i );
        y_bit[1] = y_bit[1] | (( (coins[i] >> 5) & 0x01 ) << i );
        y_bit[2] = y_bit[2] | (( (coins[i] >> 6) & 0x01 ) << i );
        y_bit[3] = y_bit[3] | (( (coins[i] >> 7) & 0x01 ) << i );
    }

    for (i = 0; i < kappa; i++) {
    	x[i]=x_bit[i];
    	y[i]=y_bit[i];}
    
}

static void unpack_bitslice_HO(uint16_t r[32], uint32_t z_bit[lambda])
{

    int i;
    uint32_t z;

    for (i = 0; i < 32; i += 2) {
        //unpack lambda bits

        z = ((((z_bit[3] & 0x02) << 2) | ((z_bit[2] & 0x02) << 1) | ((z_bit[1] & 0x02) << 0) | ((z_bit[0] & 0x02) >> 1)) << 16) | ((z_bit[3] & 0x01) << 3) | ((z_bit[2] & 0x01) << 2) | ((z_bit[1] & 0x01) << 1) | ((z_bit[0] & 0x01));

        r[i] = z&0xffff;
        r[i+1] = (z>>16)&0xffff;

        z_bit[0] = z_bit[0] >> 2;
        z_bit[1] = z_bit[1] >> 2;
        z_bit[2] = z_bit[2] >> 2;
        z_bit[3] = z_bit[3] >> 2;

    }
}

void cbd_masked_HO(uint16_t s[SABER_SHARES][SABER_L][SABER_N], const uint8_t coins[SABER_SHARES][SABER_L * SABER_POLYCOINBYTES])
{
    int32_t i, j, k1, l;
    uint16_t temp1[32][SABER_SHARES],temp[32][SABER_SHARES];
    uint32_t x_bit[SABER_SHARES][kappa], y_bit[SABER_SHARES][kappa]; //individual bits
    uint32_t z_bit[SABER_SHARES][lambda]; //individual bits

    for (i = 0; i < SABER_L; i++) {
        for (j = 0; j < SABER_N / 32; j++) { //creates 32 samples at a time
            for (l = 0; l < SABER_SHARES; l++) 
                pack_bitslice_HO(x_bit[l], y_bit[l], &coins[l][i * (SABER_MU*SABER_N/8) + 32 * j]);

            SecBitAddBitSubConsAdd_HO(x_bit, y_bit, z_bit);
                
            for (l = 0; l < SABER_SHARES; l++)
                unpack_bitslice_HO(&s[l][i][32 * j], z_bit[l]);
        
            for (k1 = 0; k1 < 32; k1 += 1) {
                for (l = 0; l < SABER_SHARES; l++)
                    temp[k1][l] = s[l][i][32 * j + k1];
                }
            for (k1 = 0; k1 < 32; k1 += 1) {
                impconvBA(temp1[k1], temp[k1], SABER_SHARES);
                    temp1[k1][0] -= kappa;
            }
            for (k1 = 0; k1 < 32; k1 += 1) {
                for (l = 0; l < SABER_SHARES; l++)
                    s[l][i][32 * j + k1] = temp1[k1][l] ;
            }
        }
    }
}

