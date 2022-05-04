#include <stdint.h>
#include "poly_mul.h"
#include <string.h>

void poly_mul(uint16_t a[SABER_N], uint16_t b[SABER_N], uint16_t res[SABER_N])
{
    memset(res, 0, 2 * SABER_N);
    toom_cook_4way_mem_asm(a, b, res);

}

void poly_mul_acc(uint16_t a[SABER_N], uint16_t b[SABER_N], uint16_t res[SABER_N])
{
    toom_cook_4way_mem_asm(a, b, res);
}