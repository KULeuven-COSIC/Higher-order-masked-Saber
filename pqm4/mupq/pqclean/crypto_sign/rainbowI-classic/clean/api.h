#ifndef PQCLEAN_RAINBOWICLASSIC_CLEAN_API_H
#define PQCLEAN_RAINBOWICLASSIC_CLEAN_API_H

#include <stddef.h>
#include <stdint.h>

#define PQCLEAN_RAINBOWICLASSIC_CLEAN_CRYPTO_SECRETKEYBYTES 103648
#define PQCLEAN_RAINBOWICLASSIC_CLEAN_CRYPTO_PUBLICKEYBYTES 161600
#define PQCLEAN_RAINBOWICLASSIC_CLEAN_CRYPTO_BYTES 66
#define PQCLEAN_RAINBOWICLASSIC_CLEAN_CRYPTO_ALGNAME "RAINBOW(16,36,32,32) - classic"

int PQCLEAN_RAINBOWICLASSIC_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);


int PQCLEAN_RAINBOWICLASSIC_CLEAN_crypto_sign_signature(
    uint8_t *sig, size_t *siglen,
    const uint8_t *m, size_t mlen, const uint8_t *sk);

int PQCLEAN_RAINBOWICLASSIC_CLEAN_crypto_sign_verify(
    const uint8_t *sig, size_t siglen,
    const uint8_t *m, size_t mlen, const uint8_t *pk);

int PQCLEAN_RAINBOWICLASSIC_CLEAN_crypto_sign(uint8_t *sm, size_t *smlen,
        const uint8_t *m, size_t mlen,
        const uint8_t *sk);

int PQCLEAN_RAINBOWICLASSIC_CLEAN_crypto_sign_open(uint8_t *m, size_t *mlen,
        const uint8_t *sm, size_t smlen,
        const uint8_t *pk);


#endif
