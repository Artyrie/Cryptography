/*
 * Copyright 2020. Heekuck Oh, all rights reserved
 * 이 프로그램은 한양대학교 ERICA 소프트웨어학부 재학생을 위한 교육용으로 제작되었습니다.
 */
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include "rsa_pss.h"
#include <stdint.h>

#if defined(SHA224)
void (*sha)(const unsigned char *, unsigned int, unsigned char *) = sha224;
#elif defined(SHA256)
void (*sha)(const unsigned char *, unsigned int, unsigned char *) = sha256;
#elif defined(SHA384)
void (*sha)(const unsigned char *, unsigned int, unsigned char *) = sha384;
#else
void (*sha)(const unsigned char *, unsigned int, unsigned char *) = sha512;
#endif

/*
 * Copyright 2020. Heekuck Oh, all rights reserved
 * rsa_generate_key() - generates RSA keys e, d and n in octet strings.
 * If mode = 0, then e = 65537 is used. Otherwise e will be randomly selected.
 * Carmichael's totient function Lambda(n) is used.
 */


void rsa_generate_key(void *_e, void *_d, void *_n, int mode)
{
    mpz_t p, q, lambda, e, d, n, gcd;
    gmp_randstate_t state;
    
    /*
     * Initialize mpz variables
     */
    mpz_inits(p, q, lambda, e, d, n, gcd, NULL);
    gmp_randinit_default(state);
    gmp_randseed_ui(state, arc4random());
    /*
     * Generate prime p and q such that 2^(RSAKEYSIZE-1) <= p*q < 2^RSAKEYSIZE
     */
    do {
        do {
            mpz_urandomb(p, state, RSAKEYSIZE/2);
        } while (mpz_probab_prime_p(p, 50) == 0);
        do {
            mpz_urandomb(q, state, RSAKEYSIZE/2);
        } while (mpz_probab_prime_p(q, 50) == 0);
        mpz_mul(n, p, q);
    } while (!mpz_tstbit(n, RSAKEYSIZE-1));
    /*
     * Generate e and d using Lambda(n)
     */
    mpz_sub_ui(p, p, 1);
    mpz_sub_ui(q, q, 1);
    mpz_lcm(lambda, p, q);
    if (mode == 0)
        mpz_set_ui(e, 65537);
    else do {
        mpz_urandomb(e, state, RSAKEYSIZE);
        mpz_gcd(gcd, e, lambda);
    } while (mpz_cmp(e, lambda) >= 0 || mpz_cmp_ui(gcd, 1) != 0);
    mpz_invert(d, e, lambda);
    /*
     * Convert mpz_t values into octet strings
     */
    mpz_export(_e, NULL, 1, RSAKEYSIZE/8, 1, 0, e);
    mpz_export(_d, NULL, 1, RSAKEYSIZE/8, 1, 0, d);
    mpz_export(_n, NULL, 1, RSAKEYSIZE/8, 1, 0, n);
    /*
     * Free the space occupied by mpz variables
     */
    mpz_clears(p, q, lambda, e, d, n, gcd, NULL);
}

/*
 * Copyright 2020. Heekuck Oh, all rights reserved
 * rsa_cipher() - compute m^k mod n
 * If m >= n then returns EM_MSG_OUT_OF_RANGE, otherwise returns 0 for success.
 */
static int rsa_cipher(void *_m, const void *_k, const void *_n)
{
    mpz_t m, k, n;
    
    /*
     * Initialize mpz variables
     */
    mpz_inits(m, k, n, NULL);
    /*
     * Convert big-endian octets into mpz_t values
     */
    mpz_import(m, RSAKEYSIZE/8, 1, 1, 1, 0, _m);
    mpz_import(k, RSAKEYSIZE/8, 1, 1, 1, 0, _k);
    mpz_import(n, RSAKEYSIZE/8, 1, 1, 1, 0, _n);
    /*
     * Compute m^k mod n
     */
    if (mpz_cmp(m, n) >= 0) {
        mpz_clears(m, k, n, NULL);
        return EM_MSG_OUT_OF_RANGE;
    }
    mpz_powm(m, m, k, n);
    /*
     * Convert mpz_t m into the octet string _m
     */
    mpz_export(_m, NULL, 1, RSAKEYSIZE/8, 1, 0, m);
    /*
     * Free the space occupied by mpz variables
     */
    mpz_clears(m, k, n, NULL);
    return 0;
}

/*
 * Copyright 2020. Heekuck Oh, all rights reserved
 * A mask generation function based on a hash function
 */
static unsigned char *mgf(const unsigned char *mgfSeed, size_t seedLen, unsigned char *mask, size_t maskLen)
{
    uint32_t i, count;
    size_t hLen;
    unsigned char *mgfIn, *p, *m;
    
    /*
     * Check if maskLen > 2^32*hLen
     */
    hLen = SHASIZE/8;
    if (maskLen > 0x0100000000*hLen)
        return NULL;
    /*
     * Generate octet string mask
     */
    if ((mgfIn = (unsigned char *)malloc(seedLen+4)) == NULL)
        return NULL;;
    memcpy(mgfIn, mgfSeed, seedLen);
    count = maskLen/hLen + (maskLen%hLen ? 1 : 0);
    if ((m = (unsigned char *)malloc(count*hLen)) == NULL)
        return NULL;
    p = (unsigned char *)&i;
    for (i = 0; i < count; i++) {
        mgfIn[seedLen] = p[3];
        mgfIn[seedLen+1] = p[2];
        mgfIn[seedLen+2] = p[1];
        mgfIn[seedLen+3] = p[0];
        (*sha)(mgfIn, seedLen+4, m+i*hLen);
    }
    /*
     * Copy the mask and free memory
     */
    memcpy(mask, m, maskLen);
    free(mgfIn); free(m);
    return mask;
}

// Merge or Divide 2 Char array
void merge2(char r[], char s1[], char s2[], uint32_t size2[], uint32_t mode) {
    uint32_t i, j, k;
    k = 0;
    i = 0;

    while(i < 2) {
        for (j = 0; j < size2[i]; j++) {
            if (i == 0) {
                if (mode == 1) {
                    r[k++] = s1[j];
                } else {
                    s1[j] = r[k++];
                }
            } else {
                if (mode == 1) {
                    r[k++] = s2[j];
                } else {
                    s2[j] = r[k++];
                }
            }
        }
        i++;
    }
}

// Merge or Divide 3 Char array
void merge3(char r[], char s1[], char s2[], char s3[], uint32_t size3[], uint32_t mode) {
    uint32_t i, j, k;
    k = 0;
    i = 0;

    while(i < 3) {
        for (j = 0; j < size3[i]; j++) {
            if (i == 0) {
                if (mode == 1) {
                    r[k++] = s1[j];
                } else {
                    s1[j] = r[k++];
                }
            } else if (i == 1) {
                if (mode == 1) {
                    r[k++] = s2[j];
                } else {
                    s2[j] = r[k++];
                }
                
            } else {
                if (mode == 1) {
                    r[k++] = s3[j];
                } else {
                    s3[j] = r[k++];
                }
            }
        }
        i++;
    }
}

// Make function of padding2 
void make_pad2(char r[], uint32_t size1) {
    uint32_t i;

    for (i = 0; i < size1; i++) {
        if (i == size1 - 1) {
            r[i] = 0x01;
        } else {
            r[i] = 0x00;
        }
    }
}

void print_val(char arr[], uint32_t size) {
    uint32_t i;

    for(i = 0; i < size; i++) {
        printf("%02x", (unsigned char)arr[i]);
    }
    printf("\n");
}

/*
 * rsassa_pss_sign - RSA Signature Scheme with Appendix
 */
int rsassa_pss_sign(const void *m, size_t mLen, const void *d, const void *n, void *s)
{
    #define PAD1SIZE 64
    #define MERGE 1
    #define DIVIDE 0

    char test_salt[SHASIZE/8];
    char test_mhash[SHASIZE/8];
    char test_pad1[PAD1SIZE/8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    char test_mp[PAD1SIZE/8 + 2 * (SHASIZE/8)];
    char test_h[SHASIZE/8];
    char test_pad2[RSAKEYSIZE/8 - 2*SHASIZE/8 - 8/8];
    char test_db[RSAKEYSIZE/8 - SHASIZE/8 - 8/8];
    char test_mgf[RSAKEYSIZE/8 - SHASIZE/8 - 8/8];
    char test_mdb[RSAKEYSIZE/8 - SHASIZE/8 - 8/8];
    char test_bc[1] = {0xbc};
    //char test_em[RSAKEYSIZE/8];
    char *test_em;
    test_em = (char *) s;
    char *test_n;
    test_n = (const char *) n;
    uint32_t i;

    // Make Salt
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, arc4random());
    mpz_t slt;
    mpz_inits(slt, NULL);
    mpz_urandomb(slt, state, SHASIZE);
    gmp_printf("Test salt : %Zx\n", slt);//
    mpz_export(&test_salt, NULL, 1, SHASIZE/8, 1, 0, slt);

    printf("Test salt : ");
    for(i = 0; i < sizeof(test_salt); i++) {
        printf("%02x", (unsigned char)test_salt[i]);
    }
    printf("\n");

    mpz_clears(slt, NULL);

    // hash(M)
    sha256(m, mLen, test_mhash);
    printf("test h : ");
    print_val(test_mhash, sizeof(test_mhash));

    // Make M'
    uint32_t size3[] = {PAD1SIZE/8, SHASIZE/8, SHASIZE/8};
    merge3(test_mp, test_pad1, test_mhash, test_salt, size3, MERGE);
    printf("test mp : ");
    print_val(test_mp, sizeof(test_mp));

    // Hash(M')
    sha256(test_mp, sizeof(test_mp), test_h);
    printf("test H : ");
    print_val(test_h, sizeof(test_h));

    // Check HASH size is valid
    if (sizeof(test_h) > SHASIZE/8) {
        return EM_HASH_TOO_LONG;
    }

    // Make pad2
    make_pad2(test_pad2, sizeof(test_pad2));
    printf("test p2 : ");
    print_val(test_pad2, sizeof(test_pad2));

    // Make DB
    uint32_t size2[] = {RSAKEYSIZE/8 - 2*SHASIZE/8 - 8/8, SHASIZE/8};
    merge2(test_db, test_pad2, test_salt, size2, MERGE);
    printf("test db : ");
    print_val(test_db, sizeof(test_db));

    // test DB last 01
    if((unsigned char)test_db[sizeof(test_db) - SHASIZE/8 - 1] != 0x01) {
        return EM_INVALID_PD2;
    }

    // Make mgf
    mgf(test_h, sizeof(test_h), test_mgf, sizeof(test_mgf));
    printf("test mgf : ");
    print_val(test_mgf, sizeof(test_mgf));

    // Make maskedDB
    for(i = 0; i < sizeof(test_mdb); i++) {
        test_mdb[i] = test_mgf[i] ^ test_db[i];
    }
    printf("test mdb : ");
    print_val(test_mdb, sizeof(test_mdb));

    // Make EM
    size3[0] = sizeof(test_mdb); size3[1] = sizeof(test_h); size3[2] = sizeof(test_bc);
    merge3(test_em, test_mdb, test_h, test_bc, size3, MERGE);
    printf("test em : ");
    print_val(test_em, (sizeof(char) * RSAKEYSIZE/8));

    // modify EM INIT
    if ((unsigned char)test_em[0] >= 0x80) {
        test_em[0] = (unsigned char)test_em[0] - 0x80;
    }
    // test EM
    if (sizeof(test_em) > RSAKEYSIZE/8) {
        return EM_MSG_TOO_LONG;
    } else if ((unsigned char)test_em[RSAKEYSIZE/8-1] != 0xbc) {
        return EM_INVALID_LAST;
    } else if ((unsigned char)test_em[0] >= 0x80) {
        return EM_INVALID_INIT;
    }
    
    // Modulus check
    for (i = 0; i < sizeof(RSAKEYSIZE/8); i++) {
        if ((unsigned char)test_n[i] > (unsigned char)test_em[i]) {
            break;
        } else {
            printf("test em range : %02hhx\n", test_em[0]);
            printf("test _n range : %02hhx\n", test_n[0]);
            return EM_MSG_OUT_OF_RANGE;
        }
    }
    

    rsa_cipher(test_em, d, n);
    printf("test r : ");
    print_val(test_em, (sizeof(char) * RSAKEYSIZE/8));

    printf("test s : %p\n", s);
    printf("test cptr : %p\n", test_em);
    print_val(s, (sizeof(char) * RSAKEYSIZE/8));

    return 0;
}

/*
 * rsassa_pss_verify - RSA Signature Scheme with Appendix
 */
int rsassa_pss_verify(const void *m, size_t mLen, const void *e, const void *n, const void *s)
{
    #define PAD1SIZE 64
    #define MERGE 1
    #define DIVIDE 0

    char test_mdb[RSAKEYSIZE/8 - SHASIZE/8 - 8/8];
    char test_h[SHASIZE/8];
    char test_bc[1];
    char test_mgf[RSAKEYSIZE/8 - SHASIZE/8 - 8/8];
    char test_db[RSAKEYSIZE/8 - SHASIZE/8 - 8/8];
    char test_pad2[RSAKEYSIZE/8 - 2*SHASIZE/8 - 8/8];
    char test_salt[SHASIZE/8];
    char test_mhash[SHASIZE/8];
    char test_pad1[PAD1SIZE/8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    char test_mp[PAD1SIZE/8 + 2 * (SHASIZE/8)];
    char *test_em;
    test_em = (char *) s;
    char *test_n;
    test_n = (const char *) n;
    uint32_t i;

    // Modulus Check
    uint32_t check = 0;
    for (i = 0; i < sizeof(test_em); i++) {
        if ((unsigned char)test_n[i] > (unsigned char)test_em[i]) {
            break;
        } else if ((unsigned char)test_n[i] == (unsigned char)test_em[i]) {
            check++;
            if (check != i + 1) {
                break;
            }
        } else {
            printf("i is %d\n", i);
            printf("test em range : %02hhx\n", test_em[i]);
            printf("test _n range : %02hhx\n", test_n[i]);
            printf("%d m : ", sizeof(test_em));
            print_val(test_em, sizeof(test_em));
            printf("%d n : ", sizeof(test_n));
            print_val(test_n, sizeof(test_n));
            return EM_MSG_OUT_OF_RANGE;
        }
    }

    // Decrypt s
    rsa_cipher(test_em, e, n);

    // test EM
    if (sizeof(s) > RSAKEYSIZE/8) {
        return EM_MSG_TOO_LONG;
    } else if ((unsigned char)test_em[RSAKEYSIZE/8-1] != 0xbc) {
        return EM_INVALID_LAST;
    } else if ((unsigned char)test_em[0] >= 0x80) {
        return EM_INVALID_INIT;
    }

    // divide mdb, mhash
    uint32_t size3[3];
    size3[0] = sizeof(test_mdb); size3[1] = sizeof(test_h); size3[2] = sizeof(test_bc);
    merge3(s, test_mdb, test_h, test_bc, size3, DIVIDE);

    // Make mgf(H)
    mgf(test_h, sizeof(test_h), test_mgf, sizeof(test_mgf));

    // test db
    for(i = 0; i < sizeof(test_db); i++) {
        test_db[i] = test_mgf[i] ^ test_mdb[i];
    }
    if ((unsigned char)test_db[0] >= 0x80) { // EM INIT modify
        test_db[0] = (unsigned char)test_db[0] - 0x80;
    }

    // test DB last 01
    if((unsigned char)test_db[sizeof(test_db) - SHASIZE/8 - 1] != 0x01) {
        return EM_INVALID_PD2;
    }
    
    // divde salt
    uint32_t size2[] = {RSAKEYSIZE/8 - 2*SHASIZE/8 - 8/8, SHASIZE/8};
    merge2(test_db, test_pad2, test_salt, size2, DIVIDE);

    // hash(M)
    sha256(m, mLen, test_mhash);

    // Make M'
    size3[0] = PAD1SIZE/8; size3[1] = SHASIZE/8; size3[2] = SHASIZE/8;
    merge3(test_mp, test_pad1, test_mhash, test_salt, size3, MERGE);

    // Hash(M')
    sha256(test_mp, sizeof(test_mp), test_mhash);

    // Check HASH size is valid
    if (sizeof(test_mhash) > SHASIZE/8) {
        return EM_HASH_TOO_LONG;
    }

    // Hash value check
    for (i = 0; i < sizeof(test_mhash); i++) {
        if (test_mhash[i] != test_h[i]) {
            return EM_HASH_MISMATCH;
        }
    }

    return 0;
}
