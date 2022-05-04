#include "Rq_mult.h"
extern void byteToShort_761(Fq*, small*);
extern void Good17x9_Rader17(Fq*, Fq*);
extern void ntt9_rader(Fq*);
extern void polymul_10x10_153_mr(Fq*, Fq*);
extern void intt9_rader(Fq*);
extern void iRader17_iGood17x9(Fq*, Fq*);
extern void mod_reduce_761(Fq*, Fq*);
/*************************************************
* Name:        Rq_mult_small
*
* Description: Computes polynomial multiplication in Z_q/(X^p-X-1)
*              with selected implementation.
*
* Arguments:
* Fq *h          : pointer to the output polynomial in R_q
* const Fq *f    : pointer to the input polynomial in R_q
* const small *g : pointer to the input polynomial in R_q
**************************************************/
void Rq_mult_small(Fq *h,const Fq *f,const small *g)
{
  int16_t g_modq[1530], fg[1530];

  byteToShort_761(h, (small*)g);
  Good17x9_Rader17(g_modq, h);
  ntt9_rader(g_modq);
  Good17x9_Rader17(fg, (Fq*)f);
  ntt9_rader(fg);
  polymul_10x10_153_mr(fg, g_modq);
  intt9_rader(fg);
  iRader17_iGood17x9(g_modq, fg);
  mod_reduce_761(h, g_modq);

}

/*************************************************
* Name:        Rq_mult_twice
*
* Description: Computes two polynomial multiplications in Z_q/(X^p-X-1)
*              with selected implementation.
*
* Arguments:
* Fq *bG          : pointer to the output polynomial in R_q
* Fq *bA          : pointer to the output polynomial in R_q
* const Fq *G    : pointer to the input polynomial in R_q
* const Fq *A    : pointer to the input polynomial in R_q
* const small *b : pointer to the input polynomial in R_q
**************************************************/
void Rq_mult_twice(Fq *bG, Fq *bA, const Fq *G, const Fq *A, const small *b){

  int16_t b_modq[1530], G_modq[1530], A_modq[1530];
  byteToShort_761(bG, (small*)b);
  Good17x9_Rader17(b_modq, bG);
  ntt9_rader(b_modq);
  Good17x9_Rader17(G_modq, (Fq*)G);
  ntt9_rader(G_modq);
  Good17x9_Rader17(A_modq, (Fq*)A);
  ntt9_rader(A_modq);
  polymul_10x10_153_mr(G_modq, b_modq);
  polymul_10x10_153_mr(A_modq, b_modq);
  intt9_rader(G_modq);
  iRader17_iGood17x9(b_modq, G_modq);
  mod_reduce_761(bG, b_modq);
  intt9_rader(A_modq);
  iRader17_iGood17x9(b_modq, A_modq);
  mod_reduce_761(bA, b_modq);
}
