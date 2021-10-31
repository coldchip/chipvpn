#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>
#include <stddef.h>

// #define the macros below to 1/0 to enable/disable the mode of operation.
//
// CBC enables AES encryption in CBC-mode of operation.
// CTR enables encryption in counter-mode.
// ECB enables the basic ECB 16-byte block algorithm. All can be enabled simultaneously.

// The #ifndef-guard allows it to be configured before #include'ing or at compile time.

#define AES128 1
//#define AES192 1
//#define AES256 1

#define AES_BLOCKLEN 16 // Block length in bytes - AES is 128b block only

#if defined(AES256) && (AES256 == 1)
    #define AES_KEYLEN 32
    #define AES_KEYEXPSIZE 240
#elif defined(AES192) && (AES192 == 1)
    #define AES_KEYLEN 24
    #define AES_KEYEXPSIZE 208
#else
    #define AES_KEYLEN 16   // Key length in bytes
    #define AES_KEYEXPSIZE 176
#endif

typedef struct _AES {
  uint8_t RoundKey[AES_KEYEXPSIZE];
  uint8_t Iv[AES_BLOCKLEN];
} AES;

void aes_set_key(AES *ctx, const uint8_t *key);
void aes_set_iv(AES *ctx, const uint8_t *iv);



// Same function for encrypting as for decrypting. 
// IV is incremented for every block, and used after encryption as XOR-compliment for output
// Suggesting https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7 for padding scheme
// NOTES: you need to set IV in ctx with AES_init_ctx_iv() or AES_ctx_set_iv()
//        no IV should ever be reused with the same key 
void aes_ctr_xcrypt(AES *ctx, uint8_t* buf, size_t length);
void aes_ctr_xcrypt_cpy(AES *ctx, uint8_t* dst, uint8_t* src, size_t length);


#endif // _AES_H_
