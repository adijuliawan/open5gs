#ifndef KMU_SHA2_HMAC_H
#define KMU_SHA2_HMAC_H

#ifdef __cplusplus
extern "C" {
#endif

#include "kmu_sha2.h"
#include <stdint.h>
#include <string.h> 
#include <stdlib.h>

typedef struct {
    kmu_sha256_ctx ctx_inside;
    kmu_sha256_ctx ctx_outside;

    /* for hmac_reinit */
    kmu_sha256_ctx ctx_inside_reinit;
    kmu_sha256_ctx ctx_outside_reinit;

    uint8_t block_ipad[KMU_SHA256_BLOCK_SIZE];
    uint8_t block_opad[KMU_SHA256_BLOCK_SIZE];
} kmu_hmac_sha256_ctx;


void kmu_hmac_sha256_init(kmu_hmac_sha256_ctx *ctx, const uint8_t *key,
                      uint32_t key_size);
void kmu_hmac_sha256_reinit(kmu_hmac_sha256_ctx *ctx);
void kmu_hmac_sha256_update(kmu_hmac_sha256_ctx *ctx, const uint8_t *message,
                        uint32_t message_len);
void kmu_hmac_sha256_final(kmu_hmac_sha256_ctx *ctx, uint8_t *mac,
                       uint32_t mac_size);
void kmu_hmac_sha256(const uint8_t *key, uint32_t key_size,
                 const uint8_t *message, uint32_t message_len,
                 uint8_t *mac, uint32_t mac_size);


#ifdef __cplusplus
}
#endif

#endif /* KMU_SHA2_HMAC_H */
