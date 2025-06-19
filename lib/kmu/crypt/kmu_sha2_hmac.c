#include "kmu_sha2_hmac.h"

/* HMAC-SHA-256 functions */

void kmu_hmac_sha256_init(kmu_hmac_sha256_ctx *ctx, const uint8_t *key,
    uint32_t key_size)
{
    uint32_t fill;
    uint32_t num;

    uint8_t key_temp[KMU_SHA256_BLOCK_SIZE];
    int i;

    if (key_size > KMU_SHA256_BLOCK_SIZE){
        num = KMU_SHA256_DIGEST_SIZE;
        kmu_sha256(key, key_size, key_temp);
    } else { /* key_size <= KMU_SHA256_BLOCK_SIZE */
        memcpy(key_temp, key, sizeof(key_temp));
        num = key_size;
    }
    fill = KMU_SHA256_BLOCK_SIZE - num;

    memset(ctx->block_ipad + num, 0x36, fill);
    memset(ctx->block_opad + num, 0x5c, fill);
    //}

    for (i = 0; i < num; i++) {
        ctx->block_ipad[i] = key_temp[i] ^ 0x36;
        ctx->block_opad[i] = key_temp[i] ^ 0x5c;
    }

    kmu_sha256_init(&ctx->ctx_inside);
    kmu_sha256_update(&ctx->ctx_inside, ctx->block_ipad, KMU_SHA256_BLOCK_SIZE);

    kmu_sha256_init(&ctx->ctx_outside);
    kmu_sha256_update(&ctx->ctx_outside, ctx->block_opad,
        KMU_SHA256_BLOCK_SIZE);

    /* for hmac_reinit */
    memcpy(&ctx->ctx_inside_reinit, &ctx->ctx_inside,
    sizeof(kmu_sha256_ctx));
    memcpy(&ctx->ctx_outside_reinit, &ctx->ctx_outside,
    sizeof(kmu_sha256_ctx));
}

void kmu_hmac_sha256_reinit(kmu_hmac_sha256_ctx *ctx)
{
    memcpy(&ctx->ctx_inside, &ctx->ctx_inside_reinit,
    sizeof(kmu_sha256_ctx));
    memcpy(&ctx->ctx_outside, &ctx->ctx_outside_reinit,
    sizeof(kmu_sha256_ctx));
}

void kmu_hmac_sha256_update(kmu_hmac_sha256_ctx *ctx, const uint8_t *message,
                        uint32_t message_len)
{
    kmu_sha256_update(&ctx->ctx_inside, message, message_len);
}

void kmu_hmac_sha256_final(kmu_hmac_sha256_ctx *ctx, uint8_t *mac,
                        uint32_t mac_size)
{
    uint8_t digest_inside[KMU_SHA256_DIGEST_SIZE];
    uint8_t mac_temp[KMU_SHA256_DIGEST_SIZE];

    kmu_sha256_final(&ctx->ctx_inside, digest_inside);
    kmu_sha256_update(&ctx->ctx_outside, digest_inside, KMU_SHA256_DIGEST_SIZE);
    kmu_sha256_final(&ctx->ctx_outside, mac_temp);
    memcpy(mac, mac_temp, mac_size);
}

void kmu_hmac_sha256(const uint8_t *key, uint32_t key_size,
                const uint8_t *message, uint32_t message_len,
                uint8_t *mac, uint32_t mac_size)
{
    kmu_hmac_sha256_ctx ctx;

    kmu_hmac_sha256_init(&ctx, key, key_size);
    kmu_hmac_sha256_update(&ctx, message, message_len);
    kmu_hmac_sha256_final(&ctx, mac, mac_size);
}

