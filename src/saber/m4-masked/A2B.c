#include "A2B.h"
#include "masksONOFF.h"

#include <string.h>

/*
-------------------------------------------
       Higher order masking functions
-------------------------------------------
*/

//////////////////////SecAdd////////////////////////////

static void SecXOR32(size_t nshares, uint32_t z[nshares], const uint32_t x[nshares], const uint32_t y[nshares])
{
	for (size_t i = 0; i < nshares; i++)
	{
		z[i] = x[i] ^ y[i];
	}
}

// [http://www.crypto-uni.lu/jscoron/publications/secconvorder.pdf, Algorithm 1]
static void SecAND32(size_t nshares, uint32_t z[nshares], const uint32_t x[nshares], const uint32_t y[nshares])
{
	uint32_t r[nshares][nshares];

	for (size_t i = 0; i < nshares; i++)
	{
		for (size_t j = (i + 1); j < nshares; j++)
		{
			r[i][j] = random_uint32();
			r[j][i] = r[i][j] ^ (x[i] & y[j]);
			r[j][i] = r[j][i] ^ (x[j] & y[i]);
		}
	}

	for (size_t i = 0; i < nshares; i++)
	{
		z[i] = x[i] & y[i];
		for (size_t j = 0; j < nshares; j++)
		{
			if (i != j)
			{
				z[i] ^= r[i][j];
			}
		}
	}
}
//secAnd for fixed shares 
void SecAnd_high32(uint32_t z[SABER_SHARES], uint32_t x[SABER_SHARES], uint32_t y[SABER_SHARES])
{
    uint16_t i,j;
	uint32_t r[SABER_SHARES][SABER_SHARES];
    uint32_t rand;

    for(i=0;i<SABER_SHARES;i++)
    	z[i]=(x[i]&y[i]);
    for(i=0;i<(SABER_SHARES-1);i++)
    {
    	for(j=(i+1);j<SABER_SHARES;j++)
    	{
    		rand=random_uint32();
    		r[i][j]=rand;
    		r[j][i]=(r[i][j]^(x[i]&y[j])^(x[j]&y[i]));
    		z[i]=z[i]^r[i][j];
    		z[j]=z[j]^r[j][i];
    	}
    }
}

static void get_bit(size_t nshares, size_t nbits, uint32_t x_bit[nshares], const uint32_t x[nshares][nbits], size_t bit)
{
	for (size_t i = 0; i < nshares; i++)
	{
		x_bit[i] = x[i][bit];
	}
}

static void write_bit(size_t nshares, size_t nbits, uint32_t x[nshares][nbits], const uint32_t x_bit[nshares], size_t bit)
{
	for (size_t i = 0; i < nshares; i++)
	{
		x[i][bit] = x_bit[i];
	}
}

// [http://www.crypto-uni.lu/jscoron/publications/secconvorder.pdf, Algorithm 2]
static void SecAdd_bitsliced(size_t nshares, size_t nbits, uint32_t z[nshares][nbits], const uint32_t x[nshares][nbits], const uint32_t y[nshares][nbits])
{
    uint32_t xXORc[nshares], xXORy[nshares], xXORyANDxXORc[nshares];
	uint32_t carry[nshares];
	uint32_t sum[nshares];
	uint32_t x_bit[nshares];
	uint32_t y_bit[nshares];

	get_bit(nshares, nbits, x_bit, x, 0);
	get_bit(nshares, nbits, y_bit, y, 0);

	SecAND32(nshares, carry, x_bit, y_bit);
	SecXOR32(nshares, sum, x_bit, y_bit);

	write_bit(nshares, nbits, z, sum, 0);

	for (size_t i = 1; i < nbits; i++)  
	{
		get_bit(nshares, nbits, x_bit, x, i);
		get_bit(nshares, nbits, y_bit, y, i);

		// sum
		SecXOR32(nshares, xXORy, x_bit, y_bit);
		SecXOR32(nshares, sum, xXORy, carry);

		// Carry out
		if (i != nbits - 1) //* nbits - 1 because we don't need carry
		{
            // [ https://eprint.iacr.org/2022/158.pdf, Algorithm 5]
            SecXOR32(nshares, xXORc, x_bit, carry);
			SecAND32(nshares, xXORyANDxXORc, xXORy, xXORc);
			SecXOR32(nshares, carry, xXORyANDxXORc, x_bit);
        }

		write_bit(nshares, nbits, z, sum, i);
	}
}

///////////////////// A2B//////////////////////


// [http://www.crypto-uni.lu/jscoron/publications/secconvorder.pdf, Algorithm 5]
__attribute__((unused)) static void expand_bitsliced(size_t from, size_t to, size_t nbits, uint32_t x[to][nbits])
{
    for (size_t i = from, j = 0; i < to; i++, j++)
    {
        for (size_t k = 0; k < nbits; k++)
        {
            x[i][k] = random_uint32();
            x[j][k] ^= x[i][k];
        }
    }
}

static void RefreshXOR_bitsliced(size_t from, size_t to, size_t nbits, uint32_t x[to][nbits])
{
    uint32_t R;

    for (size_t i = from; i < to; i++)
    {
        for (size_t k = 0; k < nbits; k++)
        {
            x[i][k] = 0;
        }
    }

    for (size_t i = 0; i < to - 1; i++)
    {
        for (size_t j = i + 1; j < to; j++)
        {
            for (size_t k = 0; k < nbits; k++)
            {
                R = random_uint32();
                x[i][k] ^= R;
                x[j][k] ^= R;
            }
        }
    }
}

static void A2B_bitsliced(size_t nshares, size_t nbits, uint32_t B_bitsliced[nshares][nbits], const uint32_t A_bitsliced[nshares][nbits])
{
    if (nshares == 1)
    {
        for (size_t i = 0; i < nbits; i++)
        {
            B_bitsliced[0][i] = A_bitsliced[0][i];
        }
        return;
    }

    uint32_t x[nshares][nbits], y[nshares][nbits];

    A2B_bitsliced(nshares / 2, nbits, &x[0], &A_bitsliced[0]);
    RefreshXOR_bitsliced(nshares / 2, nshares, nbits, x);
    A2B_bitsliced(nshares - (nshares / 2), nbits, &y[0], &A_bitsliced[nshares / 2]);
    RefreshXOR_bitsliced(nshares - (nshares / 2), nshares, nbits, y);
    SecAdd_bitsliced(nshares, nbits, B_bitsliced, x, y);
}

static void pack_bitslice(size_t nshares, size_t nbits, uint32_t x_bitsliced[nshares][nbits], const uint16_t x[32][nshares])
{
    memset(x_bitsliced, 0, nshares * nbits * sizeof(uint32_t));

    for (size_t i = 0; i < 32; i++)
    {
        for (size_t j = 0; j < nshares; j++)
        {
            for (size_t k = 0; k < nbits; k++)
            {
                x_bitsliced[j][k] = x_bitsliced[j][k] | (((x[i][j] >> k) & 1) << i);
            }
        }
    }
}

static void unpack_bitslice(size_t nshares, size_t nbits, uint16_t x[32][nshares], uint32_t x_bitsliced[nshares][nbits])
{
    for (size_t i = 0; i < 32; i++)
    {
        for (size_t j = 0; j < nshares; j++)
        {
            uint16_t tmp = 0;

            for (size_t k = 0; k < nbits; k++)
            {
                tmp |= ((x_bitsliced[j][k] & (1 << i)) >> i) << k;
            }

            x[i][j] = tmp;
        }
    }
}

void A2B_parallel_bitsliced(size_t nbits, uint16_t B[32][SABER_SHARES], const uint16_t A[32][SABER_SHARES])
{
    uint32_t A_bitsliced[SABER_SHARES][nbits];
    uint32_t B_bitsliced[SABER_SHARES][nbits];

    pack_bitslice(SABER_SHARES, nbits, A_bitsliced, A);
    A2B_bitsliced(SABER_SHARES, nbits, B_bitsliced, A_bitsliced);
    unpack_bitslice(SABER_SHARES, nbits, B, B_bitsliced);
}

// [https://github.com/KULeuven-COSIC/Revisiting-Masked-Comparison]
void A2B_keepbitsliced_B(uint32_t out[SABER_EP][SABER_SHARES][SABER_L][SABER_N/32], const uint16_t Bp[SABER_L][SABER_N][SABER_SHARES])
{
    uint32_t B1_bitsliced[SABER_SHARES][SABER_EQ];
    uint32_t B2_bitsliced[SABER_SHARES][SABER_EQ];

    // convert Bp
    for (size_t l = 0; l < SABER_L; l += 1)
    {
        for (size_t i = 0; i < SABER_N/32; i += 1)
        {
            // pack to bitslice, then A2B
            // don't unpack
            pack_bitslice(SABER_SHARES, SABER_EQ, B1_bitsliced, &Bp[l][32*i]);
            A2B_bitsliced(SABER_SHARES, SABER_EQ, B2_bitsliced, B1_bitsliced);
            for (size_t j = 0; j < SABER_SHARES; j++)
                for (size_t k = 0; k < SABER_EP; k++)
                    out[k][j][l][i] = B2_bitsliced[j][k + SABER_EQ - SABER_EP];
        }
    }
}    

void A2B_keepbitsliced_Cm(uint32_t out[SABER_ET][SABER_SHARES][SABER_N/32], const uint16_t Bp[SABER_N][SABER_SHARES])
{
    uint32_t B1_bitsliced[SABER_SHARES][SABER_EP];
    uint32_t B2_bitsliced[SABER_SHARES][SABER_EP];

    // convert Bp
    for (size_t i = 0; i < SABER_N/32; i += 1)
    {
        // pack to bitslice, then A2B
        // don't unpack
        pack_bitslice(SABER_SHARES, SABER_EP, B1_bitsliced, &Bp[32*i]);
        A2B_bitsliced(SABER_SHARES, SABER_EP, B2_bitsliced, B1_bitsliced);
        for (size_t j = 0; j < SABER_SHARES; j++)
            for (size_t k = 0; k < SABER_ET; k++)
                out[k][j][i] = B2_bitsliced[j][k + SABER_EP - SABER_ET];
    }
}

void A2B_bitsliced_msg(uint16_t msg[SABER_SHARES][SABER_N], const uint16_t vp[SABER_N][SABER_SHARES])
{
    uint32_t v1_bitsliced[SABER_SHARES][SABER_EP];
    uint32_t v2_bitsliced[SABER_SHARES][SABER_EP];

    // convert vp
    for (size_t i = 0; i < SABER_N/32; i += 1)
    {
        // pack to bitslice, then A2B
        // don't unpack
        pack_bitslice(SABER_SHARES, SABER_EP, v1_bitsliced, &vp[32*i]);
        A2B_bitsliced(SABER_SHARES, SABER_EP, v2_bitsliced, v1_bitsliced);
        for (size_t j = 0; j < SABER_SHARES; j++)
        {
            for (size_t k = 0; k < 32; k++)
            {
                msg[j][32*i + k] = (v2_bitsliced[j][SABER_EP - 1]>>k)&1;
            }    
        }
    }
}


