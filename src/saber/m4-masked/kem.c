#include "api.h"
#include "verify.h"
#include "fips202.h"
#include "fips202-masked.h"
#include "randombytes.h"
#include "SABER_indcpa.h"
#include "pack_unpack.h"
#include "masksONOFF.h"
#include <string.h>


// #ifdef PROFILE_HASHING
// #include "hal.h"
// #include "sendfn.h"
// unsigned long long Decryption_cycles, ReEncryption_cycles, sha3_512_cycles;
// #define printcycles(S, U) send_unsignedll((S), (U))
// #endif

int crypto_kem_keypair(uint8_t *pk, uint8_t *sk)
{
    indcpa_kem_keypair(pk, sk); // sk[0:SABER_INDCPA_SECRETKEYBYTES-1] <-- sk

    memcpy(sk + SABER_INDCPA_SECRETKEYBYTES, pk, SABER_INDCPA_PUBLICKEYBYTES); // sk[SABER_INDCPA_SECRETKEYBYTES:SABER_INDCPA_SECRETKEYBYTES+SABER_INDCPA_SECRETKEYBYTES-1] <-- pk

    sha3_256(sk + SABER_SECRETKEYBYTES - 64, pk, SABER_INDCPA_PUBLICKEYBYTES); // Then hash(pk) is appended.

    randombytes(sk + SABER_SECRETKEYBYTES - SABER_KEYBYTES, SABER_KEYBYTES); // Remaining part of sk contains a pseudo-random number, this is output when check in crypto_kem_dec() fails.

    return (0);
}

int crypto_kem_enc(uint8_t *c, uint8_t *k, const uint8_t *pk)
{
    uint8_t kr[64]; // Will contain key, coins
    uint8_t buf[64];

    randombytes(buf, 32);

    sha3_256(buf, buf, 32); // BUF[0:31] <-- random message (will be used as the key for client) Note: hash doesnot release system RNG output

    sha3_256(buf + 32, pk, SABER_INDCPA_PUBLICKEYBYTES); // BUF[32:63] <-- Hash(public key);  Multitarget countermeasure for coins + contributory KEM

    sha3_512(kr, buf, 64); // kr[0:63] <-- Hash(buf[0:63]), K^ <-- kr[0:31], noiseseed (r) <-- kr[32:63]

    indcpa_kem_enc(buf, kr + 32, pk, c); // buf[0:31] contains message; kr[32:63] contains randomness r;

    sha3_256(kr + 32, c, SABER_BYTES_CCA_DEC);

    sha3_256(k, kr, 64); // hash concatenation of pre-k and h(c) to k

    return (0);
}

int crypto_kem_dec(uint8_t *k, const uint8_t *c, const uint8_t *sk)
{
    uint8_t fail;
    uint8_t buf[64];
    uint8_t kr[64]; // Will contain key, coins
    const uint8_t *pk = sk + SABER_INDCPA_SECRETKEYBYTES;
    const uint8_t *hpk = sk + SABER_SECRETKEYBYTES - 64; // Save hash by storing h(pk) in sk

    indcpa_kem_dec(sk, c, buf); // buf[0:31] <-- message

    memcpy(buf + 32, hpk, 32);  // Multitarget countermeasure for coins + contributory KEM

    sha3_512(kr, buf, 64);

    fail = indcpa_kem_enc_cmp(buf, kr + 32, pk, c); //in-place verification of the re-encryption

    sha3_256(kr + 32, c, SABER_BYTES_CCA_DEC); // overwrite coins in kr with h(c)

    cmov(kr, sk + SABER_SECRETKEYBYTES - SABER_KEYBYTES, SABER_KEYBYTES, fail);

    sha3_256(k, kr, 64); // hash concatenation of pre-k and h(c) to k

    return (0);
}

/*
-------------------------------------------
       Higher order masking functions
-------------------------------------------
*/

int crypto_kem_keypair_sk_masked_HO(sk_masked_s *sksv1, const unsigned char *sk)
{
  uint32_t rand, hpk0, hpkl;
  uint32_t i,j,k;
  BS2POLVECmu(sk, sksv1->s[0]); //sksv is the secret-key
   
    for (i = 0; i < SABER_L; i++) {
        for (j = 0; j < SABER_N ; j += 2) {
            for (k = 1; k < SABER_SHARES; k++) {
                rand = random_uint32();
                sksv1->s[k][i][j] = (uint16_t)rand;
                sksv1->s[0][i][j] -= (uint16_t)rand;
                sksv1->s[k][i][j + 1] = (uint16_t)(rand >> 16);
                sksv1->s[0][i][j + 1] -= (uint16_t)(rand >> 16);
            }
        }
    }
 
    memcpy(sksv1->pk, sk + SABER_INDCPA_SECRETKEYBYTES, SABER_INDCPA_PUBLICKEYBYTES);
    memcpy(sksv1->hpk[0], sk + SABER_SECRETKEYBYTES - 64, 32);
    memcpy(sksv1->z, sk + SABER_SECRETKEYBYTES - SABER_KEYBYTES, SABER_KEYBYTES);
    
    for (i = 0; i < 32; i += 4) {
        for (j = 1; j < SABER_SHARES; j++) {
            rand = random_uint32();
            memcpy(&hpk0, &sksv1->hpk[0][i], 4);
            memcpy(&hpkl, &sksv1->hpk[j][i], 4);
            hpkl = rand;
            hpk0 ^= rand;
            memcpy(&sksv1->hpk[0][i], &hpk0, 4);
            memcpy(&sksv1->hpk[j][i], &hpkl, 4);
        }
    }

    return (0);
}


int crypto_kem_dec_masked_HO(unsigned char *k, const unsigned char *c,sk_masked_s *sk)
{
    int i, fail;  
    const unsigned char *pk = sk->pk;
    unsigned char kr[SABER_SHARES][64],r[SABER_SHARES][32],buf[SABER_SHARES][64],m[SABER_SHARES][32]; 
    int j;

    // #ifdef PROFILE_HASHING
    // unsigned long long t0, t1;
    // t0 = hal_get_time();
    // #endif

    indcpa_kem_dec_masked_HO(sk->s, c, m);	

    // #ifdef PROFILE_HASHING
    // t1 = hal_get_time();
    // Decryption_cycles = t1 - t0;
    // printcycles("Decryption cycles cycles:", Decryption_cycles);
    // #endif
    

    for (i = 0; i < SABER_SHARES; i++) {                            // buf1[0:31] <-- message1, buf2[0:31] <-- message2
        memcpy(&buf[i][0], &m[i][0], 32);
        memcpy(&buf[i][32], sk->hpk[i], 32);
    }
 
    // #ifdef PROFILE_HASHING
    // unsigned long long t2, t3;
    // t2 = hal_get_time();
    // #endif

    sha3_512_masked_HO(kr, 64, buf);  
    
    // #ifdef PROFILE_HASHING
    // t3 = hal_get_time();
    // sha3_512_cycles = t3 - t2;
    // printcycles("sha3_512_cycles cycles cycles:",sha3_512_cycles);
    // #endif

    for (i = 0; i < SABER_SHARES; i++) {
        memcpy(r[i], &kr[i][32], 32);
    }

    // #ifdef PROFILE_HASHING
    // unsigned long long t4, t5;
    // t4 = hal_get_time();
    // #endif

    fail = indcpa_kem_enc_cmp_masked_HO(m, r, pk, c);

    // #ifdef PROFILE_HASHING
    // t5 = hal_get_time();
    // ReEncryption_cycles = t5 - t4;
    // printcycles("ReEncryption cycles cycles:", ReEncryption_cycles);
    // #endif

    sha3_256(&kr[0][32], c, SABER_BYTES_CCA_DEC);        		     // overwrite coins in kr with h(c)  
    for(j=1;j<SABER_SHARES;j++){
        for(i=0;i<32;i++){   // Save hash by storing h(pk) in sk 
            kr[0][i] ^= (kr[j][i] * fail);
        }
    }
    cmov(kr[0], sk->z, SABER_KEYBYTES, !fail); 
    sha3_256(k, kr[0], 64);                          	   	       // hash concatenation of pre-k and h(c) to k

    return(0);	
}


