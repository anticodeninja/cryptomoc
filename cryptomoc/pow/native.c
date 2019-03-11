#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/pem.h>

enum { BLOCK_WIDTH = 16, BLOCK_HEIGHT = 16, BLOCK_SIZE = BLOCK_WIDTH * BLOCK_HEIGHT };

// BlockFormat: 16xBlockId, 16xPrevBlockId, 64xSource, 64xTarget, 32xR, 32xS, 64xSHA256

size_t get_block_size() {
    return BLOCK_SIZE;
}

void write_prev_block_id(uint8_t block[BLOCK_SIZE], uint8_t prev_block_id[BLOCK_WIDTH]) {
    memcpy(&block[BLOCK_WIDTH], prev_block_id, BLOCK_WIDTH);
}

void increment_block_id(uint8_t block[BLOCK_SIZE]) {
    size_t index = BLOCK_WIDTH - 1;
    while (block[index] == 0xFF) {
        block[index] = 0;
        index -= 1;
    }
    block[index] += 1;
}

void print_block(uint8_t block[BLOCK_SIZE]) {
    for (size_t i = 0; i < BLOCK_HEIGHT; ++i) {
        for (size_t j = 0; j < BLOCK_WIDTH; ++j) {
            printf("%02x", block[i * BLOCK_WIDTH + j]);
        }
        printf("\n");
    }
    printf("\n");
}

void print_debug(char* message, uint8_t *data, size_t length) {
    printf("%s: ", message);
    for (size_t i = 0; i < length; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int check_digest(uint8_t* digest) {
    return digest[0] == 0x00 && digest[1] == 0x00 && digest[2] == 0x00;
}

int write_target(uint8_t block[BLOCK_SIZE], const char* filename) {
    int ret = 1;

    uint8_t buffer[65];
    BIO *in = NULL;
    BN_CTX *ctx = NULL;
    EC_KEY *ec_key = NULL;
    const EC_GROUP *ec_group = NULL;
    const EC_POINT *ec_public_point = NULL;
    BIGNUM *ec_public_key = NULL;

    if ((in = BIO_new_file(filename, "r")) == NULL) goto end;
    if ((ctx = BN_CTX_new()) == NULL) goto end;
    if ((ec_key = PEM_read_bio_EC_PUBKEY(in, NULL, NULL, NULL)) == NULL) goto end;
    if ((ec_group = EC_KEY_get0_group(ec_key)) == NULL) goto end;
    if ((ec_public_point = EC_KEY_get0_public_key(ec_key)) == NULL) goto end;
    if ((ec_public_key = EC_POINT_point2bn(ec_group, ec_public_point,
                                           EC_KEY_get_conv_form(ec_key), NULL, ctx)) == NULL) goto end;
    if (BN_num_bytes(ec_public_key) != 65) goto end;
    if (BN_bn2bin(ec_public_key, buffer) != 65) goto end;

    memcpy(&block[96], &buffer[1], 64);
    ret = 0;

 end:
    if (ec_key) EC_KEY_free(ec_key);
    if (ec_public_key) BN_free(ec_public_key);
    if (ctx) BN_CTX_free(ctx);
    if (in) BIO_free_all(in);
    return ret;
}

int write_source_and_sign(uint8_t block[BLOCK_SIZE], const char* filename) {
    int ret = 1;

    uint8_t buffer[65];
    uint8_t digest[SHA256_DIGEST_LENGTH];
    BIO *in = NULL;
    BN_CTX *ctx = NULL;
    EC_KEY *ec_key = NULL;
    const EC_GROUP *ec_group = NULL;
    const EC_POINT *ec_public_point = NULL;
    ECDSA_SIG* ec_sign = NULL;
    BIGNUM *ec_public_key = NULL;

    if ((ctx = BN_CTX_new()) == NULL) goto end;
    if ((in = BIO_new_file(filename, "r")) == NULL) goto end;
    if ((ec_key = PEM_read_bio_ECPrivateKey(in, NULL, NULL, NULL)) == NULL) goto end;
    if ((ec_group = EC_KEY_get0_group(ec_key)) == NULL) goto end;
    if ((ec_public_point = EC_KEY_get0_public_key(ec_key)) == NULL) goto end;
    if ((ec_public_key = EC_POINT_point2bn(ec_group, ec_public_point,
                                           EC_KEY_get_conv_form(ec_key), NULL, ctx)) == NULL) goto end;
    if (BN_num_bytes(ec_public_key) != 65) goto end;
    if (BN_bn2bin(ec_public_key, buffer) != 65) goto end;
    memcpy(&block[32], &buffer[1], 64);

    SHA256(&block[16], 80, digest);
    if ((ec_sign = ECDSA_do_sign(digest, SHA256_DIGEST_LENGTH, ec_key)) == NULL) goto end;
    if (BN_bn2bin(ec_sign->r, &block[160]) != 32) goto end;
    if (BN_bn2bin(ec_sign->s, &block[192]) != 32) goto end;
    ret = 0;

 end:
    if (ec_sign) ECDSA_SIG_free(ec_sign);
    if (ec_public_key) BN_free(ec_public_key);
    if (ec_key) EC_KEY_free(ec_key);
    if (in) BIO_free_all(in);
    if (ctx) BN_CTX_free(ctx);
    return ret;
}

void solve_digest(uint8_t block[BLOCK_SIZE]) {
    uint8_t digest[SHA256_DIGEST_LENGTH];
    for (;;) {
        SHA256(block, BLOCK_SIZE - SHA256_DIGEST_LENGTH, digest);
        if (check_digest(digest)) break;
        increment_block_id(block);
    }
    memcpy(&block[BLOCK_SIZE - SHA256_DIGEST_LENGTH], &digest[0], SHA256_DIGEST_LENGTH);
}

int check_block(uint8_t block[BLOCK_SIZE], uint8_t prev_block_id[BLOCK_WIDTH]) {
    int ret = 0;

    uint8_t buffer[65] = { 0x04 };
    uint8_t digest[SHA256_DIGEST_LENGTH];
    BN_CTX *ctx = NULL;
    EC_GROUP *ec_group = NULL;
    EC_POINT *ec_public_point = NULL;
    EC_KEY *ec_key = NULL;
    BIGNUM *ec_public_key = NULL;
    ECDSA_SIG* ec_sign = NULL;

    // PrevBlock
    if (memcmp(&block[16], prev_block_id, BLOCK_WIDTH) != 0) goto end;

    // Signature
    memcpy(&buffer[1], &block[32], 64);
    SHA256(&block[16], 80, digest);
    if ((ctx = BN_CTX_new()) == NULL) goto end;
    if ((ec_public_key = BN_bin2bn(buffer, 65, NULL)) == NULL) goto end;
    if ((ec_group = EC_GROUP_new_by_curve_name(NID_secp256k1)) == NULL) goto end;
    if ((ec_public_point = EC_POINT_bn2point(ec_group, ec_public_key, NULL, ctx)) == NULL) goto end;
    if ((ec_key = EC_KEY_new_by_curve_name(NID_secp256k1)) == NULL) goto end;
    if (EC_KEY_set_public_key(ec_key, ec_public_point) != 1) goto end;
    if ((ec_sign = ECDSA_SIG_new()) == NULL) goto end;
    if (BN_bin2bn(&block[160], 32, ec_sign->r) == NULL) goto end;
    if (BN_bin2bn(&block[192], 32, ec_sign->s) == NULL) goto end;
    if (ECDSA_do_verify(digest, SHA256_DIGEST_LENGTH, ec_sign, ec_key) != 1) goto end;

    // Digest
    if (!check_digest(&block[BLOCK_SIZE - SHA256_DIGEST_LENGTH])) goto end;

    ret = 1;
 end:
    if (ec_sign) ECDSA_SIG_free(ec_sign);
    if (ec_public_key) BN_free(ec_public_key);
    if (ec_public_point) EC_POINT_free(ec_public_point);
    if (ec_group) EC_GROUP_free(ec_group);
    if (ec_key) EC_KEY_free(ec_key);
    if (ctx) BN_CTX_free(ctx);
    return ret;
}

int main() {
    uint8_t block[BLOCK_SIZE] = { 0 };
    uint8_t prev_block_id[BLOCK_WIDTH] = { 0 };

    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC_RAW, &start);

    write_prev_block_id(block, prev_block_id);
    write_target(block, "slave.pub");
    write_source_and_sign(block, "master.key");
    solve_digest(block);

    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC_RAW, &end);

    uint64_t delta = end.tv_sec - start.tv_sec;
    printf("Spent: %lu\n", delta);

    print_block(block);

    if (check_block(block, prev_block_id))
        printf("%s\n", "Valid block");
    else
        printf("%s\n", "Invalid block");
}
