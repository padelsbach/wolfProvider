/* test_cipher.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
 *
 * This file is part of wolfProvider.
 *
 * wolfProvider is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfProvider is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wolfProvider. If not, see <http://www.gnu.org/licenses/>.
 */

#include "unit.h"

#if defined(WP_HAVE_DES3CBC) || defined(WP_HAVE_AESCBC) || \
    defined(WP_HAVE_AESECB) || defined(WP_HAVE_AESCTR) || \
    defined(WP_HAVE_AESCFB)

static int test_cipher_enc(const EVP_CIPHER *cipher,
                           unsigned char *key, unsigned char *iv,
                           unsigned char *msg, int len, unsigned char *enc,
                           int pad)
{
    int err;
    EVP_CIPHER_CTX *ctx;
    int encLen;
    int fLen = 0;

    err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    if (err == 0) {
       err = EVP_EncryptInit(ctx, cipher, key, iv) != 1;
    }
    if (err == 0) {
        err = EVP_CIPHER_CTX_set_padding(ctx, pad) != 1;
    }
    if (err == 0) {
        err = EVP_EncryptUpdate(ctx, enc, &encLen, msg, len) != 1;
    }
    if (err == 0) {
        err = EVP_EncryptFinal_ex(ctx, enc + encLen, &fLen) != 1;
    }

    if (err == 0) {
        PRINT_BUFFER("Encrypted", enc, encLen + fLen);
    }

    EVP_CIPHER_CTX_free(ctx);

    return err;
}

#endif

#if defined(WP_HAVE_DES3CBC) || defined(WP_HAVE_AESCBC) || \
    defined(WP_HAVE_AESECB)

static int test_cipher_dec(const EVP_CIPHER *cipher,
                           unsigned char *key, unsigned char *iv,
                           unsigned char *msg, int len, unsigned char *enc,
                           int encLen, unsigned char *dec, int pad)
{
    int err;
    EVP_CIPHER_CTX *ctx;
    int decLen;
    int fLen;

    err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    if (err == 0) {
        err = EVP_DecryptInit(ctx, cipher, key, iv) != 1;
    }
    if (err == 0) {
        err = EVP_CIPHER_CTX_set_padding(ctx, pad) != 1;
    }
    if (err == 0) {
        err = EVP_DecryptUpdate(ctx, dec, &decLen, enc, encLen) != 1;
    }
    if (err == 0) {
        err = EVP_DecryptFinal_ex(ctx, dec + decLen, &fLen) != 1;
    }

    if (err == 0) {
        PRINT_BUFFER("Decrypted", dec, decLen + fLen);

        if (decLen + fLen != (int)len || memcmp(dec, msg, len) != 0) {
            err = 1;
        }
    }

    EVP_CIPHER_CTX_free(ctx);

    return err;
}

static int test_cipher_enc_dec(void *data, const char *cipher, int keyLen,
    int ivLen)
{
    int err = 0;
    unsigned char msg[16] = "Test pattern";
    unsigned char key[32];
    unsigned char iv[16];
    unsigned char enc[sizeof(msg) + 16];
    unsigned char dec[sizeof(msg) + 16];
    EVP_CIPHER *ocipher;
    EVP_CIPHER *wcipher;

    (void)data;

    ocipher = EVP_CIPHER_fetch(osslLibCtx, cipher, "");
    wcipher = EVP_CIPHER_fetch(wpLibCtx, cipher, "");

    if (RAND_bytes(key, keyLen) != 1) {
        err = 1;
    }
    if (err == 0) {
        if (RAND_bytes(iv, ivLen) != 1) {
            err = 1;
        }
    }

    if (err == 0) {
        PRINT_BUFFER("Key", key, keyLen);
        PRINT_BUFFER("IV", iv, ivLen);
        PRINT_BUFFER("Message", msg, sizeof(msg));
    }

    if (err == 0) {
        PRINT_MSG("Encrypt with OpenSSL - padding");
        err = test_cipher_enc(ocipher, key, iv, msg, sizeof(msg), enc, 1);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with wolfprovider - padding");
        err = test_cipher_dec(wcipher, key, iv, msg, sizeof(msg), enc,
                              sizeof(msg) + ivLen, dec, 1);
    }

    if (err == 0) {
        PRINT_MSG("Encrypt with wolfprovider - padding");
        err = test_cipher_enc(wcipher, key, iv, msg, sizeof(msg), enc, 1);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with OpenSSL - padding");
        err = test_cipher_dec(ocipher, key, iv, msg, sizeof(msg), enc,
                              sizeof(msg) + ivLen, dec, 1);
    }

    if (err == 0) {
        PRINT_MSG("Encrypt with OpenSSL - no pad");
        err = test_cipher_enc(ocipher, key, iv, msg, sizeof(msg), enc, 0);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with wolfprovider - no pad");
        err = test_cipher_dec(wcipher, key, iv, msg, sizeof(msg), enc,
                              sizeof(msg), dec, 0);
    }

    if (err == 0) {
        PRINT_MSG("Encrypt with wolfprovider - no pad");
        err = test_cipher_enc(wcipher, key, iv, msg, sizeof(msg), enc, 0);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt with OpenSSL - no pad");
        err = test_cipher_dec(ocipher, key, iv, msg, sizeof(msg), enc,
                              sizeof(msg), dec, 0);
    }

    EVP_CIPHER_free(wcipher);
    EVP_CIPHER_free(ocipher);

    return err;
}

#endif

#if defined(WP_HAVE_DES3CBC) || defined(WP_HAVE_AESCBC) || \
    defined(WP_HAVE_AESECB) || defined(WP_HAVE_AESCTR) || \
    defined(WP_HAVE_AESCFB)


/******************************************************************************/

static int test_stream_enc(const EVP_CIPHER *cipher,
                           unsigned char *key, unsigned char *iv,
                           unsigned char *msg, int len, unsigned char *enc,
                           unsigned char *encExp, int expLen)
{
    int err;
    EVP_CIPHER_CTX *ctx;
    int eLen = 0;
    int encLen;
    int i;
    int j;

    err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    for (i = 1; (err == 0) && (i <= (int)len); i++) {
        eLen = 0;
        err = EVP_EncryptInit(ctx, cipher, key, iv) != 1;

        for (j = 0; (err == 0) && (j < (int)len); j += i) {
            int l = len - j;
            if (i < l)
                l = i;
            err = EVP_EncryptUpdate(ctx, enc + eLen, &encLen, msg + j, l) != 1;
            if (err == 0) {
                eLen += encLen;
            }
        }

        if (err == 0) {
            err = EVP_EncryptFinal_ex(ctx, enc + eLen, &encLen) != 1;
            if (err == 0) {
                eLen += encLen;
            }
        }
        if (err == 0 && (eLen != expLen || memcmp(enc, encExp, expLen) != 0)) {
            err = 1;
        }
    }
    if (err == 0) {
        PRINT_BUFFER("Encrypted", enc, eLen);
    }

    EVP_CIPHER_CTX_free(ctx);

    return err;
}

static int test_stream_dec(const EVP_CIPHER *cipher,
                           unsigned char *key, unsigned char *iv,
                           unsigned char *msg, int len, unsigned char *enc,
                           int encLen, unsigned char *dec)
{
    int err;
    EVP_CIPHER_CTX *ctx;
    int dLen;
    int decLen = 0;
    int i;
    int j;

    err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    for (i = 1; (err == 0) && (i <= (int)encLen); i++) {
        dLen = 0;
        err = EVP_DecryptInit(ctx, cipher, key, iv) != 1;

        for (j = 0; (err == 0) && (j < (int)encLen); j += i) {
            int l = encLen - j;
            if (i < l)
                l = i;
            err = EVP_DecryptUpdate(ctx, dec + dLen, &decLen, enc + j, l) != 1;
            if (err == 0) {
                dLen += decLen;
            }
        }

        if (err == 0) {
            err = EVP_DecryptFinal_ex(ctx, dec + dLen, &decLen) != 1;
            if (err == 0) {
                dLen += decLen;
            }
        }
        if ((err == 0) && ((dLen != len) || (memcmp(dec, msg, len) != 0))) {
            PRINT_BUFFER("Decrypted", dec, dLen);
            err = 1;
        }
    }
    if (err == 0) {
        PRINT_BUFFER("Decrypted", dec, len);
    }

    EVP_CIPHER_CTX_free(ctx);

    return err;
}

static int test_stream_enc_dec(void *data, const char *cipher, int keyLen,
    int ivLen, int msgLen, int pad)
{
    int err = 0;
    unsigned char msg[16] = "Test pattern";
    unsigned char key[32];
    unsigned char iv[16];
    unsigned char enc[sizeof(msg) + 16];
    unsigned char encExp[sizeof(msg) + 16];
    unsigned char dec[sizeof(msg) + 16];
    int encLen;
    EVP_CIPHER *ocipher;
    EVP_CIPHER *wcipher;

    ocipher = EVP_CIPHER_fetch(osslLibCtx, cipher, "");
    wcipher = EVP_CIPHER_fetch(wpLibCtx, cipher, "");

    if (pad) {
        encLen = (msgLen + ivLen) & (~(ivLen-1));
    }
    else {
        encLen = msgLen;
    }

    (void)data;

    if (RAND_bytes(key, keyLen) != 1) {
        printf("generate key failed\n");
        err = 1;
    }
    if (err == 0) {
        if (RAND_bytes(iv, ivLen) != 1) {
            printf("generate iv failed\n");
            err = 1;
        }
    }

    if (err == 0) {
        PRINT_BUFFER("Key", key, keyLen);
        PRINT_BUFFER("IV", iv, ivLen);
        PRINT_BUFFER("Message", msg, sizeof(msg));
    }

    if (err == 0) {
        PRINT_MSG("Encrypt with OpenSSL");
        err = test_cipher_enc(ocipher, key, iv, msg, msgLen, encExp, 1);
    }

    if (err == 0) {
        PRINT_MSG("Encrypt Stream with wolfprovider");
        err = test_stream_enc(wcipher, key, iv, msg, msgLen, enc, encExp,
                              encLen);
    }
    if (err == 0) {
        PRINT_MSG("Decrypt Stream with wolfprovider");
        err = test_stream_dec(wcipher, key, iv, msg, msgLen, enc, encLen,
                              dec);
    }

    EVP_CIPHER_free(wcipher);
    EVP_CIPHER_free(ocipher);

    return err;
}

static int test_cipher_null_zero_ex(void *data, const char *cipher, int keyLen,
    int ivLen)
{
    int err = 0;
    unsigned char msg[16] = "Test pattern";
    unsigned char key[32];
    unsigned char iv[16];
    unsigned char enc[sizeof(msg) + 16];
    EVP_CIPHER *ocipher;
    EVP_CIPHER *wcipher;
    EVP_CIPHER_CTX *ctx;

    (void)data;

    ocipher = EVP_CIPHER_fetch(osslLibCtx, cipher, "");
    wcipher = EVP_CIPHER_fetch(wpLibCtx, cipher, "");

    if (RAND_bytes(key, keyLen) != 1) {
        err = 1;
    }
    if (err == 0) {
        if (RAND_bytes(iv, ivLen) != 1) {
            err = 1;
        }
    }

    /* Test that a final call with NULL/NULL/0 yields the correct return
     * value, flow mimics that of libssh2 */
    err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    if (err == 0) {
       err = EVP_CipherInit(ctx, ocipher, key, iv, 1) != 1;
    }
    if (err == 0) {
        err = EVP_Cipher(ctx, enc, msg, sizeof(msg)) <= 0;
    }
    /* Return is 0, not negative value for NULL/NULL/0 input */
    if (err == 0) {
        err = EVP_Cipher(ctx, NULL, NULL, 0) != 0;
    }
    EVP_CIPHER_CTX_free(ctx);

    err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    if (err == 0) {
       err = EVP_CipherInit(ctx, wcipher, key, iv, 1) != 1;
    }
    if (err == 0) {
        err = EVP_Cipher(ctx, enc, msg, sizeof(msg)) <= 0;
    }
    /* Return is 0, not negative value for NULL/NULL/0 input */
    if (err == 0) {
        err = EVP_Cipher(ctx, NULL, NULL, 0) != 0;
    }
    EVP_CIPHER_CTX_free(ctx);

    EVP_CIPHER_free(wcipher);
    EVP_CIPHER_free(ocipher);

    return err;
}

int test_cipher_null_zero(void *data)
{
    int err = 0;

#ifdef WP_HAVE_AESECB
    err = test_cipher_null_zero_ex(data, "AES-256-ECB", 32, 16);
#endif
#ifdef WP_HAVE_AESCBC
    if (err == 0) {
        err = test_cipher_null_zero_ex(data, "AES-256-CBC", 32, 16);
    }
#endif
#ifdef WP_HAVE_AESCTR
    if (err == 0) {
        err = test_cipher_null_zero_ex(data, "AES-256-CTR", 32, 16);
    }
#endif
#ifdef WP_HAVE_AESCFB
    if (err == 0) {
        err = test_cipher_null_zero_ex(data, "AES-256-CFB", 32, 16);
    }
#endif

    return err;
}

#endif /* WP_HAVE_DES3CBC || WP_HAVE_AESCBC */

/******************************************************************************/

#ifdef WP_HAVE_DES3CBC


int test_des3_cbc(void *data)
{
    return test_cipher_enc_dec(data, "DES-EDE3-CBC", 24, 8);
}

/******************************************************************************/

int test_des3_cbc_stream(void *data)
{
    int err;

    err = test_stream_enc_dec(data, "DES-EDE3-CBC", 24, 8, 16, 1);
    if (err == 0)
        err = test_stream_enc_dec(data, "DES-EDE3-CBC", 24, 8, 1, 1);
    if (err == 0)
        err = test_stream_enc_dec(data, "DES-EDE3-CBC", 24, 8, 7, 1);

    return err;
}

#endif /* WP_HAVE_DES3CBC */

/******************************************************************************/

#ifdef WP_HAVE_AESECB

int test_aes128_ecb(void *data)
{
    return test_cipher_enc_dec(data, "AES-128-ECB", 16, 16);
}

/******************************************************************************/

int test_aes192_ecb(void *data)
{
    return test_cipher_enc_dec(data, "AES-192-ECB", 24, 16);
}

/******************************************************************************/

int test_aes256_ecb(void *data)
{
    return test_cipher_enc_dec(data, "AES-256-ECB", 32, 16);
}

/******************************************************************************/

int test_aes128_ecb_stream(void *data)
{
    int err;

    err = test_stream_enc_dec(data, "AES-128-ECB", 16, 16, 16, 1);
    if (err == 0)
        err = test_stream_enc_dec(data, "AES-128-ECB", 16, 16, 1, 1);

    return err;
}

/******************************************************************************/

int test_aes192_ecb_stream(void *data)
{
    int err;

    err = test_stream_enc_dec(data, "AES-192-ECB", 24, 16, 15, 1);
    if (err == 0)
        err = test_stream_enc_dec(data, "AES-192-ECB", 24, 16, 2, 1);

    return err;
}

/******************************************************************************/

int test_aes256_ecb_stream(void *data)
{
    int err;

    err = test_stream_enc_dec(data, "AES-256-ECB", 32, 16, 14, 1);
    if (err == 0)
        err = test_stream_enc_dec(data, "AES-256-ECB", 32, 16, 3, 1);

    return err;
}

#endif /* WP_HAVE_AESECB */

/******************************************************************************/

#ifdef WP_HAVE_AESCBC

int test_aes128_cbc(void *data)
{
    return test_cipher_enc_dec(data, "AES-128-CBC", 16, 16);
}

/******************************************************************************/

int test_aes192_cbc(void *data)
{
    return test_cipher_enc_dec(data, "AES-192-CBC", 24, 16);
}

/******************************************************************************/

int test_aes256_cbc(void *data)
{
    return test_cipher_enc_dec(data, "AES-256-CBC", 32, 16);
}

/******************************************************************************/

int test_aes128_cbc_stream(void *data)
{
    int err;

    err = test_stream_enc_dec(data, "AES-128-CBC", 16, 16, 16, 1);
    if (err == 0)
        err = test_stream_enc_dec(data, "AES-128-CBC", 16, 16, 1, 1);

    return err;
}

/******************************************************************************/

int test_aes192_cbc_stream(void *data)
{
    int err;

    err = test_stream_enc_dec(data, "AES-192-CBC", 24, 16, 15, 1);
    if (err == 0)
        err = test_stream_enc_dec(data, "AES-192-CBC", 24, 16, 2, 1);

    return err;
}

/******************************************************************************/

int test_aes256_cbc_stream(void *data)
{
    int err;

    err = test_stream_enc_dec(data, "AES-256-CBC", 32, 16, 14, 1);
    if (err == 0)
        err = test_stream_enc_dec(data, "AES-256-CBC", 32, 16, 3, 1);

    return err;
}

#endif /* WP_HAVE_AESCBC */

/******************************************************************************/

#ifdef WP_HAVE_AESCTR

int test_aes128_ctr_stream(void *data)
{
    int err;

    err = test_stream_enc_dec(data, "AES-128-CTR", 16, 16, 16, 0);
    if (err == 0)
        err = test_stream_enc_dec(data, "AES-128-CTR", 16, 16, 1, 0);

    return err;
}

/******************************************************************************/

int test_aes192_ctr_stream(void *data)
{
    int err;

    err = test_stream_enc_dec(data, "AES-192-CTR", 24, 16, 15, 0);
    if (err == 0)
        err = test_stream_enc_dec(data, "AES-192-CTR", 24, 16, 2, 0);

    return err;
}

/******************************************************************************/

int test_aes256_ctr_stream(void *data)
{
    int err;

    err = test_stream_enc_dec(data, "AES-256-CTR", 32, 16, 14, 0);
    if (err == 0)
        err = test_stream_enc_dec(data, "AES-256-CTR", 32, 16, 3, 0);

    return err;
}

#endif /* WP_HAVE_AESCTR */

#ifdef WP_HAVE_AESCFB

int test_aes128_cfb_stream(void *data)
{
    int err;

    err = test_stream_enc_dec(data, "AES-128-CFB", 16, 16, 16, 0);
    if (err == 0)
        err = test_stream_enc_dec(data, "AES-128-CFB", 16, 16, 1, 0);

    return err;
}

/******************************************************************************/

int test_aes192_cfb_stream(void *data)
{
    int err;

    err = test_stream_enc_dec(data, "AES-192-CFB", 24, 16, 15, 0);
    if (err == 0)
        err = test_stream_enc_dec(data, "AES-192-CFB", 24, 16, 2, 0);

    return err;
}

/******************************************************************************/

int test_aes256_cfb_stream(void *data)
{
    int err;

    err = test_stream_enc_dec(data, "AES-256-CFB", 32, 16, 14, 0);
    if (err == 0)
        err = test_stream_enc_dec(data, "AES-256-CFB", 32, 16, 3, 0);

    return err;
}

#endif /* WP_HAVE_AESCFB */

#ifdef WP_HAVE_AESCBC

int test_aes256_cbc_multiple(void *data)
{
    /* Test vector from libmemcached/libhashkit */
    static const unsigned char key_data[] = {
        0x5f, 0x5f, 0x5f, 0x5f, 0x43, 0x5f, 0x41, 0x5f,
        0x54, 0x5f, 0x43, 0x5f, 0x48, 0x5f, 0x5f, 0x5f,
        0x5f, 0x54, 0x5f, 0x45, 0x5f, 0x53, 0x5f, 0x54,
        0x5f, 0x5f, 0x5f, 0x5f, 0x30, 0x00, 0x00, 0x00
    };

    static const unsigned char plain_text[] = {
        0x72, 0x65, 0x70, 0x6c, 0x61, 0x63, 0x65, 0x64,
        0x20, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x2c, 0x20,
        0x74, 0x68, 0x69, 0x63, 0x68, 0x20, 0x69, 0x73,
        0x20, 0x6c, 0x6f, 0x6e, 0x67, 0x65, 0x72, 0x20,
        0x74, 0x68, 0x61, 0x6e, 0x20, 0x41, 0x45, 0x53,
        0x5f, 0x42, 0x4c, 0x4f, 0x43, 0x4b, 0x5f, 0x53,
        0x49, 0x5a, 0x45
    };
    static const int plain_text_len = sizeof(plain_text);

    static const unsigned char aes_iv[] = {
        0x44, 0x63, 0xff, 0xd3, 0x79, 0xcf, 0x04, 0x74,
        0x9e, 0x75, 0xa2, 0x71, 0xa4, 0x2c, 0xc7, 0x0a
    };

    static const unsigned char ciphertext_exp[] = {
        0x75, 0xdd, 0x24, 0xf5, 0xc1, 0x5c, 0x34, 0x65,
        0xaf, 0xd3, 0xa9, 0x82, 0x74, 0xe2, 0xf3, 0xa1,
        0x35, 0x95, 0x5a, 0x89, 0x6f, 0x59, 0xb9, 0xa2,
        0x84, 0xec, 0xa8, 0x54, 0x9f, 0xcc, 0x6d, 0xe3,
        0x99, 0xfc, 0xf0, 0xa3, 0xc4, 0x03, 0xc3, 0x56,
        0xec, 0x6d, 0x1c, 0xcd, 0xe1, 0xc2, 0x17, 0xa0,
        0x51, 0x0b, 0x00, 0x87, 0xde, 0x43, 0x8a, 0xf6,
        0x1b, 0x03, 0x2c, 0x7f, 0x68, 0x67, 0x11, 0x72
    };

    (void)data;
    int err = 0;

    EVP_CIPHER_CTX *ctx_enc = NULL;
    EVP_CIPHER_CTX *ctx_dec = NULL;

    if (err == 0) {
        ctx_enc = EVP_CIPHER_CTX_new();
        ctx_dec = EVP_CIPHER_CTX_new();
        if (ctx_dec == NULL || ctx_enc == NULL) {
            PRINT_MSG("EVP_CIPHER_CTX_new failed");
            err = 1;
        }
        else {
            PRINT_MSG("CTXs created");
        }
    }

    if (err == 0) {
        if (EVP_EncryptInit_ex(ctx_enc, EVP_aes_256_cbc(), NULL, key_data, aes_iv) != 1
            || EVP_DecryptInit_ex(ctx_dec, EVP_aes_256_cbc(), NULL, key_data, aes_iv) != 1) {
            PRINT_MSG("EVP_EncryptInit_ex or EVP_DecryptInit_ex failed");
            err = 1;
        }
        else {
            PRINT_MSG("EVP_EncryptInit_ex and EVP_DecryptInit_ex succeeded");
        }
    }

    /* Test that we can encrypt and decrypt multiple times without creating 
     * a new context. We should get the same result each time: same ciphertext
     * when encrypting and same plaintext when decrypting. */
    for (int i = 0; i < 8; i++) {
        int cipher_text_len = plain_text_len + EVP_CIPHER_CTX_block_size(ctx_enc);
        int decrypted_text_len = 0;
        int final_len = 0;
        unsigned char* cipher_text = malloc(cipher_text_len);
        unsigned char* decrypted_text = malloc(plain_text_len);

        PRINT_MSG("Test iteration: %d", i);

        if (cipher_text == NULL) {
            PRINT_MSG("Memory allocation failed");
            err = 1;
        }

        if (err == 0) {
            if (EVP_EncryptInit_ex(ctx_enc, NULL, NULL, NULL, NULL) != 1
                || EVP_EncryptUpdate(ctx_enc, cipher_text, &cipher_text_len, plain_text, plain_text_len) != 1
                || EVP_EncryptFinal_ex(ctx_enc, cipher_text + cipher_text_len, &final_len) != 1) {
                PRINT_MSG("Encrypt failed");
                err = 1;
            }
            else {
                cipher_text_len += final_len;
                PRINT_BUFFER("Plain text    ", plain_text, plain_text_len);
                PRINT_BUFFER("Cipher text   ", cipher_text, cipher_text_len);
            }
        }

        if (err == 0) {
            if (cipher_text_len != sizeof(ciphertext_exp)) {
                PRINT_MSG("Cipher text length does not match expected value");
                err = 1;
            }
        }

        if (err == 0) {
            if (memcmp(cipher_text, ciphertext_exp, sizeof(ciphertext_exp)) != 0) {
                PRINT_MSG("Cipher text does not match expected value");
                err = 1;
            } else {
                PRINT_MSG("Cipher text matches expected value");
            }
        }

        if (err == 0) {
            if (EVP_DecryptInit_ex(ctx_dec, NULL, NULL, NULL, NULL) != 1
                || EVP_DecryptUpdate(ctx_dec, decrypted_text, &decrypted_text_len, cipher_text, cipher_text_len) != 1
                || EVP_DecryptFinal_ex(ctx_dec, decrypted_text + decrypted_text_len, &final_len) != 1) {
                PRINT_MSG("Decrypt failed");
                err = 1;
            }
            else {
                decrypted_text_len += final_len;
                PRINT_BUFFER("Decrypted text", decrypted_text, decrypted_text_len);
            }
        }

        if (err == 0) {
            if (plain_text_len != decrypted_text_len) {
                PRINT_MSG("Decrypted text length does not match original");
                err = 1;
            }
        }

        if (err == 0) {
            int res = memcmp(plain_text, decrypted_text, plain_text_len);
            if (res != 0) {
                PRINT_MSG("Decrypted text does not match original");
                err = 1;
            } else {
                PRINT_MSG("Cipher test passed successfully");
            }
        }
    }

    return err;
}

#endif /* WP_HAVE_AESCBC */
