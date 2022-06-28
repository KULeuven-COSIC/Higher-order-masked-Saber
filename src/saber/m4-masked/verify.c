#include "verify.h"
#include "A2B.h"


/* b = 1 means mov, b = 0 means don't mov*/
void cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b)
{
    size_t i;

    b = -b;
    for (i = 0; i < len; i++) {
        r[i] ^= b & (x[i] ^ r[i]);
    }
}

/*
-------------------------------------------
       Higher order masking functions
-------------------------------------------
*/

static void poly_comp(uint32_t t_y[SABER_ET][SABER_SHARES][SABER_N/32],uint16_t v[SABER_SHARES][SABER_N],uint16_t v_prime[SABER_N])
{
	uint16_t i,j,e_u;
	uint16_t x[SABER_N][SABER_SHARES];
	
	for(i=0;i<SABER_N;i++)
	{
		e_u=(((v_prime[i])<<(SABER_EP-SABER_ET))+(1<<(SABER_EP-SABER_ET)));
		
		for(j=0;j<SABER_SHARES;j++)
			x[i][j]=v[j][i]&(SABER_P-1);
		
		x[i][SABER_SHARES-1]=(x[i][SABER_SHARES-1]-e_u)&(SABER_P-1);
	}	

	A2B_keepbitsliced_Cm(t_y, x);

}



static void poly_comp_vect(uint32_t t_w[SABER_EP][SABER_SHARES][SABER_L][SABER_N/32],uint16_t u[SABER_SHARES][SABER_L][SABER_N],uint16_t u_prime[SABER_L][SABER_N])
{
	uint16_t i,j,k,e_u;
	uint16_t x[SABER_L][SABER_N][SABER_SHARES];
	
	for(k=0;k<SABER_L;k++)
	{
		for(i=0;i<SABER_N;i++)
		{
			e_u=((u_prime[k][i])<<((SABER_EQ-SABER_EP)))+(1<<(SABER_EQ-SABER_EP));
			
			for(j=0;j<SABER_SHARES;j++)
				x[k][i][j]=u[j][k][i]&(SABER_Q-1);
			
			x[k][i][SABER_SHARES-1]=(x[k][i][SABER_SHARES-1]-e_u)&(SABER_Q-1);
		}
	}	

	A2B_keepbitsliced_B(t_w, x);

}

static void	last_SecAnd(uint32_t t_y[SABER_SHARES][SABER_N/32])
{
	uint16_t i,k;
	uint16_t j;
	uint32_t temp1[SABER_SHARES],temp2[SABER_SHARES],temp3[SABER_SHARES];

	for(j=4;j>=1;j=(j/2))
	{
		for(i=0;i<j;i++)
		{
			for(k=0;k<SABER_SHARES;k++)
			{
				temp1[k]=t_y[k][i];
				temp2[k]=t_y[k][i+j];
			}
			SecAnd_high32(temp3,temp1,temp2);
			for(k=0;k<SABER_SHARES;k++)
			{
				t_y[k][i]=temp3[k];
			}
		}
	}	

	for(j=16;j>=1;j=(j/2))
	{
		for(k=0;k<SABER_SHARES;k++)
		{
			temp1[k]=t_y[k][0]&((1<<j)-1);
			temp2[k]=(t_y[k][0]>>j)&((1<<j)-1);
		}
		SecAnd_high32(temp3,temp1,temp2);
		for(k=0;k<SABER_SHARES;k++)
		{
			t_y[k][0]=temp3[k]&((1<<j)-1);
		}
	}	
}

static void reduced_SecAnd(uint8_t b[SABER_SHARES],uint32_t t_w1[SABER_EP][SABER_SHARES][SABER_L][SABER_N/32], uint32_t t_y1[SABER_ET][SABER_SHARES][SABER_N/32])
{
	uint32_t t_w[SABER_SHARES][SABER_L][SABER_N/32],t_y[SABER_SHARES][SABER_N/32];
	uint16_t i,j,k,l;
	uint32_t temp1[SABER_SHARES],temp2[SABER_SHARES],temp3[SABER_SHARES];

	// Secure And for 4 bits of message contain share of ciphertext
	for(j=0;j<(SABER_N/32);j++)
	{
		for(k=0;k<SABER_SHARES;k++)
		{
			t_y[k][j]=t_y1[0][k][j];
		}
	}

	for(l=1;l<SABER_ET;l++)
	{
		for(j=0;j<(SABER_N/32);j++)
		{
			for(k=0;k<SABER_SHARES;k++)
			{
				temp1[k]=t_y[k][j];
				temp2[k]=t_y1[l][k][j];
			}
			SecAnd_high32(temp3,temp1,temp2);
			for(k=0;k<SABER_SHARES;k++)
			{
				t_y[k][j]=temp3[k];
			}
		}
	}
	
	// Secure And for 10 bits of key contain share of ciphertext
	for(i=0;i<SABER_L;i++)
	{
		for(j=0;j<(SABER_N/32);j++)
		{
			for(k=0;k<SABER_SHARES;k++)
			{
				t_w[k][i][j]=t_w1[0][k][i][j];
			}
		}
	}	
	
	for(l=1;l<SABER_EP;l++)
	{
		for(i=0;i<SABER_L;i++)
		{
			for(j=0;j<(SABER_N/32);j++)
			{
				for(k=0;k<SABER_SHARES;k++)
				{
					temp1[k]=t_w[k][i][j];
					temp2[k]=t_w1[l][k][i][j];
				}
				SecAnd_high32(temp3,temp1,temp2);
				for(k=0;k<SABER_SHARES;k++)
				{
					t_w[k][i][j]=temp3[k];
				}
			}
		}
	}
	
    //Performed Secure And on previous two results
	for(i=0;i<SABER_L;i++)
	{
		for(j=0;j<(SABER_N/32);j++)
		{
			for(k=0;k<SABER_SHARES;k++)
			{
				temp1[k]=t_y[k][j];
				temp2[k]=t_w[k][i][j];
			}
			SecAnd_high32(temp3,temp1,temp2);
			for(k=0;k<SABER_SHARES;k++)
			{
				t_y[k][j]=temp3[k];
			}
		}
	}

	// Secure And on 256 bits
	last_SecAnd(t_y);
	
	for(k=0;k<SABER_SHARES;k++)
	{
		b[k]=t_y[k][0];
	}
}

// Masked comparison
void masked_comparison_simple(uint8_t b[SABER_SHARES],uint16_t u[SABER_SHARES][SABER_L][SABER_N],uint16_t v[SABER_SHARES][SABER_N],uint16_t u_prime[SABER_L][SABER_N],uint16_t v_prime[SABER_N])
{

	uint32_t t_w1[SABER_EP][SABER_SHARES][SABER_L][SABER_N/32],t_y1[SABER_ET][SABER_SHARES][SABER_N/32];

	// Perform A2B and (SABER_EQ - SABER_EP) bits shift on Key share of ciphertext
	poly_comp_vect(t_w1,u,u_prime);

	// Perform A2B and (SABER_EP - SABER_ET) bits shift on Key share of ciphertext
	poly_comp(t_y1,v,v_prime);

	// SecAnd on 8704 bits
	reduced_SecAnd(b, t_w1, t_y1);

}


