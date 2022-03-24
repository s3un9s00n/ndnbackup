/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
//
// Created by 이상현 on 2022/03/24.
//

#ifndef NDN_CXX_SECURITY_TRANSFORM_FPE_CIPHER_HPP
#define NDN_CXX_SECURITY_TRANSFORM_FPE_CIPHER_HPP

#include <openssl/aes.h>
#include <openssl/bn.h>
#include <string.h>

# define FF3_ROUNDS 8
# define FF3_TWEAK_SIZE 8

# define ceil2(x, bit) ( ((x) >> (bit)) + ( ((x) & ((1 << (bit)) - 1)) > 0 ) )
# define floor2(x, bit) ( (x) >> (bit) )

/*
 * FPE
 */

struct fpe_key_st {
    unsigned int tweaklen;
    unsigned char *tweak;
    unsigned int radix;
    AES_KEY aes_enc_ctx;
};

typedef struct fpe_key_st FPE_KEY;

FPE_KEY* FPE_ff3_create_key(const char *key, const char *tweak, unsigned int radix);
FPE_KEY* FPE_ff3_1_create_key(const char *key, const char *tweak, unsigned int radix);

void FPE_ff3_delete_key(FPE_KEY *key);

void FPE_ff3_encrypt(char *plaintext, char *ciphertext, FPE_KEY *key);
void FPE_ff3_decrypt(char *ciphertext, char *plaintext, FPE_KEY *key);

/*
 * FPE-LOCL
 */

void pow_uv(BIGNUM *pow_u, BIGNUM *pow_v, unsigned int x, int u, int v, BN_CTX *ctx);

void map_chars(char str[], unsigned int result[]);
void inverse_map_chars(unsigned int result[], char str[], int len);
void hex2chars(const char hex[], unsigned char result[]);

void display_as_hex(char *name, unsigned char *k, unsigned int klen);


#endif //NDN_CXX_SECURITY_TRANSFORM_FPE_CIPHER_HPP
