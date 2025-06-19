
#ifndef KMU_SHA2_H
#define KMU_SHA2_H


#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif


#define KMU_SHA256_DIGEST_SIZE ( 256 / 8)
#define KMU_SHA256_BLOCK_SIZE  ( 512 / 8)

typedef struct {
    uint32_t tot_len;
    uint32_t len;
    uint8_t block[2 * KMU_SHA256_BLOCK_SIZE];
    uint32_t h[8];
} kmu_sha256_ctx;


void kmu_sha256_init(kmu_sha256_ctx * ctx);
void kmu_sha256_update(kmu_sha256_ctx *ctx, const uint8_t *message,
                   uint32_t len);
void kmu_sha256_final(kmu_sha256_ctx *ctx, uint8_t *digest);
void kmu_sha256(const uint8_t *message, uint32_t len, uint8_t *digest);


#ifdef __cplusplus
}
#endif

#endif /* KMU_SHA2_H */
