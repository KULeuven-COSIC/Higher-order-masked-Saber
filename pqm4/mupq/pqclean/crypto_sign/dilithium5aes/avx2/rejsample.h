#ifndef PQCLEAN_DILITHIUM5AES_AVX2_REJSAMPLE_H
#define PQCLEAN_DILITHIUM5AES_AVX2_REJSAMPLE_H
#include "params.h"
#include "symmetric.h"
#include <stdint.h>

#define REJ_UNIFORM_NBLOCKS ((768+STREAM128_BLOCKBYTES-1)/STREAM128_BLOCKBYTES)
#define REJ_UNIFORM_BUFLEN (REJ_UNIFORM_NBLOCKS*STREAM128_BLOCKBYTES)

#define REJ_UNIFORM_ETA_NBLOCKS ((136+STREAM256_BLOCKBYTES-1)/STREAM256_BLOCKBYTES)
#define REJ_UNIFORM_ETA_BUFLEN (REJ_UNIFORM_ETA_NBLOCKS*STREAM256_BLOCKBYTES)

extern const uint8_t PQCLEAN_DILITHIUM5AES_AVX2_idxlut[256][8];

unsigned int PQCLEAN_DILITHIUM5AES_AVX2_rej_uniform_avx(int32_t *r, const uint8_t buf[REJ_UNIFORM_BUFLEN + 8]);

unsigned int PQCLEAN_DILITHIUM5AES_AVX2_rej_eta_avx(int32_t *r, const uint8_t buf[REJ_UNIFORM_BUFLEN]);

#endif
