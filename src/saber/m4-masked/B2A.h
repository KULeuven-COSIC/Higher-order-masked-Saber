#ifndef B2A
#define B2A

#include <stdint.h>
#include <stddef.h>
#include "SABER_params.h"
#include "masksONOFF.h"


void impconvBA(uint16_t *D,uint16_t *x,int n);
void impconvBA_32(uint32_t *D,uint32_t *x,int n);

#endif
